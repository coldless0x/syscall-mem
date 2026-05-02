#include "syscall_gate.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <conio.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

namespace {

void log_plus(const char* fmt, ...) {
  std::fputs("[+] ", stdout);
  va_list a;
  va_start(a, fmt);
  std::vprintf(fmt, a);
  va_end(a);
  std::fputc('\n', stdout);
}

void log_minus(const char* fmt, ...) {
  std::fputs("[-] ", stderr);
  va_list a;
  va_start(a, fmt);
  std::vfprintf(stderr, fmt, a);
  va_end(a);
  std::fputc('\n', stderr);
}

void log_get_last_error(const char* api_call) {
  const DWORD gle = GetLastError();
  char* sys = nullptr;
  const DWORD fl = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                        FORMAT_MESSAGE_IGNORE_INSERTS,
                                    nullptr, gle, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                    reinterpret_cast<char*>(&sys), 0, nullptr);
  (void)fl;
  if (sys) {
    for (char* p = sys + std::strlen(sys); p > sys && (p[-1] == '\r' || p[-1] == '\n');)
      *--p = '\0';
  }
  log_minus("%s observed GetLastError()=%lu (0x%08lX)%s%s", api_call,
            static_cast<unsigned long>(gle), static_cast<unsigned long>(gle), sys ? " | " : "",
            sys ? sys : "");
  if (sys)
    LocalFree(sys);
}

void log_ntstatus_op(const char* op, LONG status, HANDLE proc, void* remote, void* local,
                     size_t length, size_t number_of_bytes) {
  log_minus(
      "%s returned NTSTATUS=0x%08lX (sign bit %s) Handle=%p BaseAddress=%p Buffer=%p "
      "Length=%zu NumberOfBytes=%zu",
      op, static_cast<unsigned long>(static_cast<ULONG>(status)),
      (status < 0) ? "set (!NT_SUCCESS)" : "clear (NT_SUCCESS)", proc, remote, local, length,
      number_of_bytes);
}

void log_memcmp_first_diff(const char* label, const unsigned char* exp, const unsigned char* got,
                           size_t len) {
  std::size_t i = 0;
  for (; i < len; ++i) {
    if (exp[i] != got[i])
      break;
  }
  if (i >= len) {
    log_minus("%s: compared %zu bytes, no difference found (unexpected)", label, len);
    return;
  }
  log_minus("%s: first unequal offset=%zu expected_byte=0x%02X actual_byte=0x%02X total_len=%zu",
            label, i, exp[i], got[i], len);
  const std::size_t lo = i > 8 ? i - 8 : 0;
  const std::size_t hi = (std::min)(len, i + 8);
  char line_exp[3 * 32] = {};
  char line_got[3 * 32] = {};
  std::size_t pe = 0;
  std::size_t pg = 0;
  for (std::size_t j = lo; j < hi && pe + 4 < sizeof(line_exp); ++j) {
    pe += static_cast<std::size_t>(std::snprintf(line_exp + pe, sizeof(line_exp) - pe, "%02X ",
                                                 static_cast<unsigned>(exp[j])));
  }
  for (std::size_t j = lo; j < hi && pg + 4 < sizeof(line_got); ++j) {
    pg += static_cast<std::size_t>(std::snprintf(line_got + pg, sizeof(line_got) - pg, "%02X ",
                                                 static_cast<unsigned>(got[j])));
  }
  log_minus("%s: context bytes [%zu..%zu) expected: %s", label, lo, hi, line_exp);
  log_minus("%s: context bytes [%zu..%zu) actual:   %s", label, lo, hi, line_got);
}

DWORD pid_by_image(const wchar_t* image) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    log_get_last_error("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)");
    return 0;
  }

  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (!Process32FirstW(snap, &pe)) {
    log_get_last_error("Process32FirstW(snapshot)");
    CloseHandle(snap);
    return 0;
  }

  DWORD pid = 0;
  do {
    if (_wcsicmp(pe.szExeFile, image) == 0) {
      pid = pe.th32ProcessID;
      break;
    }
  } while (Process32NextW(snap, &pe));

  CloseHandle(snap);
  return pid;
}

void wait_exit() {
  std::fflush(stdout);
  std::fflush(stderr);
  std::fputs("[+] press any key to exit...\n", stdout);
  std::fflush(stdout);
  (void)_getch();
}

constexpr const wchar_t* k_notepad = L"notepad.exe";

struct GateReadProbeCtx {
  SyscallGate* gate = nullptr;
  HANDLE proc = nullptr;
  void* remote = nullptr;
  void* local = nullptr;
  size_t len = 0;
  LONG status = 0;
  size_t got = 0;
};

DWORD WINAPI thread_gate_read_probe(void* param) {
  auto* c = static_cast<GateReadProbeCtx*>(param);
  size_t n = 0;
  const NTSTATUS nts = c->gate->read_mem(c->proc, c->remote, c->local, c->len, &n);
  c->status = static_cast<LONG>(nts);
  c->got = n;
  return 0;
}

}  // namespace

int main() {
  int exit_code = 0;
  SyscallGate gate;
  bool gate_live = false;
  HANDLE proc = nullptr;
  void* remote = nullptr;
  DWORD pid = 0;
  bool used_notepad = false;
  const DWORD access =
      PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
  const char* payload = "RW via syscall gate — ok";
  size_t len = std::strlen(payload) + 1;
  size_t wrote = 0;
  size_t got = 0;
  NTSTATUS st = 0;
  std::vector<char> buf;
  const DWORD k_probe_wait_ms = 8000;
  GateReadProbeCtx pctx{};
  HANDLE worker = nullptr;
  DWORD wret = 0;

  log_plus("syscall-mem | direct NtRead/NtWrite (syscall gates) | x64");
  log_plus("resolving ntdll stubs / building gates...");

  if (!gate.init()) {
    log_minus("SyscallGate::init() returned false. detail: %s",
              gate.diagnostic()[0] ? gate.diagnostic() : "(no diagnostic string set)");
    exit_code = 1;
    goto end;
  }
  gate_live = true;
  log_plus("gates online (NtReadVirtualMemory + NtWriteVirtualMemory)");
  log_plus("SSN read=0x%X write=0x%X (from ntdll stub)", gate.ssn_read(), gate.ssn_write());

  pid = pid_by_image(k_notepad);
  used_notepad = pid != 0;

  if (!used_notepad) {
    pid = GetCurrentProcessId();
    log_plus("%ls not found — using current process pid=%lu (open notepad for remote test)",
             k_notepad, static_cast<unsigned long>(pid));
  } else {
    log_plus("picked target: %ls pid=%lu", k_notepad, static_cast<unsigned long>(pid));
  }

  proc = OpenProcess(access, FALSE, pid);
  if (!proc) {
    log_minus("OpenProcess(Access=0x%08lX, Inherit=FALSE, ProcessId=%lu) returned NULL",
              static_cast<unsigned long>(access), static_cast<unsigned long>(pid));
    log_get_last_error("OpenProcess");
    exit_code = 1;
    goto end;
  }
  log_plus("OpenProcess ok Handle=%p", proc);

  remote = VirtualAllocEx(proc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) {
    log_minus(
        "VirtualAllocEx(Process=%p, Address=NULL, Size=%zu, MEM_COMMIT|MEM_RESERVE, "
        "PAGE_READWRITE) returned NULL",
        proc, len);
    log_get_last_error("VirtualAllocEx");
    exit_code = 1;
    goto end;
  }
  log_plus("VirtualAllocEx -> BaseAddress=%p RegionSize=%zu", remote, len);

  buf.assign(len, 0);
  log_plus("NtReadVirtualMemory (gate) probe: reading %zu bytes from remote BaseAddress=%p", len,
           remote);
  std::fflush(stdout);

  pctx = {};
  pctx.gate = &gate;
  pctx.proc = proc;
  pctx.remote = remote;
  pctx.local = buf.data();
  pctx.len = len;
  worker = CreateThread(nullptr, 0, thread_gate_read_probe, &pctx, 0, nullptr);
  if (!worker) {
    log_minus("CreateThread(NtReadVirtualMemory probe) returned NULL");
    log_get_last_error("CreateThread");
    exit_code = 1;
    goto end;
  }
  wret = WaitForSingleObject(worker, k_probe_wait_ms);
  if (wret != WAIT_OBJECT_0) {
    log_minus("WaitForSingleObject(probe thread) returned %lu (0x%08lX); timeout_ms=%lu",
              static_cast<unsigned long>(wret), static_cast<unsigned long>(wret),
              static_cast<unsigned long>(k_probe_wait_ms));
    if (wret == WAIT_TIMEOUT) {
      log_minus(
          "observed: NtReadVirtualMemory syscall did not return within %lu ms — thread still "
          "running; likely stuck in kernel wait or external block (SSN/CET/AV).",
          static_cast<unsigned long>(k_probe_wait_ms));
    }
    TerminateThread(worker, 1);
    CloseHandle(worker);
    exit_code = 1;
    goto end;
  }
  CloseHandle(worker);
  worker = nullptr;
  st = static_cast<NTSTATUS>(pctx.status);
  got = pctx.got;

  if (!NT_SUCCESS(st)) {
    log_ntstatus_op("NtReadVirtualMemory (syscall gate) [probe]", pctx.status, proc, remote,
                    buf.data(), len, got);
    exit_code = 1;
    goto end;
  }
  log_plus("probe NtReadVirtualMemory OK NumberOfBytes=%zu NTSTATUS=0x%08lX",
           got, static_cast<unsigned long>(st));
  if (got != len) {
    log_minus("probe: NT_SUCCESS but NumberOfBytes=%zu != Length=%zu", got, len);
    exit_code = 1;
    goto end;
  }

  log_plus("NtWriteVirtualMemory (gate): Length=%zu LocalBuffer=%p RemoteBase=%p", len,
           static_cast<const void*>(payload), remote);
  std::fflush(stdout);

  wrote = 0;
  st = gate.write_mem(proc, remote, payload, len, &wrote);
  if (!NT_SUCCESS(st)) {
    log_ntstatus_op("NtWriteVirtualMemory (syscall gate)", static_cast<LONG>(st), proc, remote,
                    const_cast<void*>(static_cast<const void*>(payload)), len, wrote);
    exit_code = 1;
    goto end;
  }
  if (wrote != len) {
    log_minus(
        "NtWriteVirtualMemory returned NTSTATUS=0x%08lX (NT_SUCCESS) but NumberOfBytes=%zu "
        "!= Length=%zu",
        static_cast<unsigned long>(st), wrote, len);
    exit_code = 1;
    goto end;
  }
  log_plus("NtWriteVirtualMemory OK NumberOfBytes=%zu", wrote);

  buf.assign(len, 0);
  got = 0;
  st = gate.read_mem(proc, remote, buf.data(), len, &got);
  if (!NT_SUCCESS(st)) {
    log_ntstatus_op("NtReadVirtualMemory (syscall gate) [verify]", static_cast<LONG>(st), proc,
                    remote, buf.data(), len, got);
    exit_code = 1;
    goto end;
  }
  if (got != len) {
    log_minus(
        "verify read: NTSTATUS=0x%08lX NT_SUCCESS but NumberOfBytes=%zu != Length=%zu",
        static_cast<unsigned long>(st), got, len);
    exit_code = 1;
    goto end;
  }
  log_plus("verify NtReadVirtualMemory OK NumberOfBytes=%zu", got);

  if (std::memcmp(buf.data(), payload, len) != 0) {
    log_memcmp_first_diff("post-write readback vs payload",
                          reinterpret_cast<const unsigned char*>(payload),
                          reinterpret_cast<const unsigned char*>(buf.data()), len);
    exit_code = 1;
    goto end;
  }
  log_plus("memcmp: all %zu bytes match payload", len);

  if (!VirtualFreeEx(proc, remote, 0, MEM_RELEASE)) {
    log_minus("VirtualFreeEx(Process=%p, BaseAddress=%p, MEM_RELEASE) returned 0", proc, remote);
    log_get_last_error("VirtualFreeEx");
  } else {
    log_plus("VirtualFreeEx released BaseAddress=%p", remote);
  }
  remote = nullptr;

  CloseHandle(proc);
  proc = nullptr;
  log_plus("CloseHandle(Process) ok");

  if (gate_live) {
    gate.shutdown();
    gate_live = false;
  }
  log_plus("done. exit_code=0");

end:
  if (remote && proc) {
    if (!VirtualFreeEx(proc, remote, 0, MEM_RELEASE)) {
      log_minus("cleanup VirtualFreeEx(Process=%p, Base=%p) returned 0", proc, remote);
      log_get_last_error("VirtualFreeEx (cleanup)");
    }
  }
  if (proc) {
    if (!CloseHandle(proc))
      log_get_last_error("CloseHandle (cleanup)");
  }
  if (gate_live)
    gate.shutdown();

  wait_exit();
  return exit_code;
}
