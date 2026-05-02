#include "syscall_gate.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

static void print_ntstatus(const char* what, NTSTATUS st) {
  std::fprintf(stderr, "%s: NTSTATUS 0x%08lX\n", what, static_cast<unsigned long>(st));
}

int main() {
  SyscallGate gate;
  if (!gate.init()) {
    std::fputs("init failed (ntdll exports or SSN parse)\n", stderr);
    return 1;
  }

  HANDLE self = GetCurrentProcess();
  const char* msg = "syscall write/read roundtrip";
  size_t msg_len = std::strlen(msg) + 1;

  void* block = VirtualAlloc(nullptr, msg_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!block) {
    std::fputs("VirtualAlloc failed\n", stderr);
    return 1;
  }

  size_t moved = 0;
  NTSTATUS st = gate.write_mem(self, block, msg, msg_len, &moved);
  if (!NT_SUCCESS(st) || moved != msg_len) {
    print_ntstatus("NtWriteVirtualMemory (syscall gate)", st);
    VirtualFree(block, 0, MEM_RELEASE);
    return 1;
  }

  std::vector<char> buf(msg_len, 0);
  st = gate.read_mem(self, block, buf.data(), msg_len, &moved);
  if (!NT_SUCCESS(st) || moved != msg_len) {
    print_ntstatus("NtReadVirtualMemory (syscall gate)", st);
    VirtualFree(block, 0, MEM_RELEASE);
    return 1;
  }

  std::printf("remote @ %p: %s\n", block, buf.data());

  VirtualFree(block, 0, MEM_RELEASE);
  gate.shutdown();
  return 0;
}
