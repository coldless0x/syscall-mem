#include "syscall_gate.hpp"

#include <Psapi.h>

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>

#pragma comment(lib, "Psapi.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

namespace {

constexpr std::size_t k_export_scan_bytes = 384;
constexpr std::size_t k_max_gap_load_to_syscall = 96;
constexpr std::size_t k_forward_r10_to_load_window = 80;

bool ssn_plausible(std::uint32_t v) {
  return v != 0 && v <= 0x3FFFFFu;
}

bool ptr_in_module(const std::uint8_t* p, const std::uint8_t* base, std::size_t size) {
  if (!p || !base || size < 4)
    return false;
  return p >= base && p <= base + size - 4;
}

bool read_u32_from_module(const std::uint8_t* abs, const std::uint8_t* base, std::size_t mod_size,
                          std::uint32_t* out) {
  if (!out || !ptr_in_module(abs, base, mod_size))
    return false;
  std::memcpy(out, abs, sizeof(std::uint32_t));
  return true;
}

// mov r10, rcx ends at k+3; load insn starts at j — require k+3 <= j.
bool has_mov_r10_rcx_before(const std::uint8_t* code, std::size_t j) {
  if (j < 3)
    return false;
  for (std::ptrdiff_t k = static_cast<std::ptrdiff_t>(j) - 3; k >= 0; --k) {
    const auto ku = static_cast<std::size_t>(k);
    if (code[ku] == 0x4C && code[ku + 1] == 0x8B && code[ku + 2] == 0xD1 && ku + 3 <= j)
      return true;
  }
  return false;
}

// Some ntdll builds emit mov eax before mov r10,rcx; both must appear before syscall.
bool stub_has_r10_for_load(const std::uint8_t* code, std::size_t nbytes, std::size_t load_j,
                           std::size_t load_end, std::size_t syscall_si) {
  if (has_mov_r10_rcx_before(code, load_j))
    return true;
  for (std::size_t k = load_end; k + 3 <= syscall_si && k + 3 < nbytes; ++k) {
    if (code[k] == 0x4C && code[k + 1] == 0x8B && code[k + 2] == 0xD1)
      return true;
  }
  return false;
}

bool try_fastpath_contiguous(const std::uint8_t* code, std::size_t nbytes, std::uint32_t* out) {
  for (std::size_t i = 0; i + 8 < nbytes; ++i) {
    if (code[i] != 0x4C || code[i + 1] != 0x8B || code[i + 2] != 0xD1 || code[i + 3] != 0xB8)
      continue;
    std::uint32_t id = 0;
    std::memcpy(&id, code + i + 4, sizeof(id));
    if (!ssn_plausible(id))
      continue;
    const std::size_t after = i + 8;
    for (std::size_t t = after; t + 1 < nbytes && t <= after + k_max_gap_load_to_syscall; ++t) {
      if (code[t] == 0x0F && code[t + 1] == 0x05) {
        *out = id;
        return true;
      }
    }
  }
  return false;
}

// mov eax, dword ptr [rip+disp32] — 7 bytes; RIP = code + j + 7.
bool decode_mov_eax_rip(const std::uint8_t* code, std::size_t nbytes, std::size_t j,
                        const std::uint8_t* mod_base, std::size_t mod_size, std::uint32_t* id,
                        std::size_t* load_end) {
  if (j + 7 > nbytes || !id || !load_end)
    return false;
  if (code[j] != 0x8B || code[j + 1] != 0x05)
    return false;

  std::int32_t disp = 0;
  std::memcpy(&disp, code + j + 2, sizeof(disp));
  const auto rip = reinterpret_cast<std::uintptr_t>(code + j + 7);
  const auto* tgt = reinterpret_cast<const std::uint8_t*>(
      static_cast<std::uintptr_t>(static_cast<std::intptr_t>(rip) + static_cast<std::intptr_t>(disp)));

  std::uint32_t v = 0;
  if (!read_u32_from_module(tgt, mod_base, mod_size, &v) || !ssn_plausible(v))
    return false;

  *id = v;
  *load_end = j + 7;
  return true;
}

bool skip_export_prologue(const std::uint8_t* code, std::size_t nbytes, std::size_t* out_o) {
  if (!out_o || nbytes == 0)
    return false;
  std::size_t p = 0;
  while (p < nbytes && code[p] == 0x90)
    ++p;
  if (p + 4 <= nbytes && code[p] == 0xF3 && code[p + 1] == 0x0F && code[p + 2] == 0x1E &&
      code[p + 3] == 0xFA)
    p += 4;
  while (p < nbytes && code[p] == 0x90)
    ++p;
  if (p + 2 <= nbytes && code[p] == 0x8B && code[p + 1] == 0xFF)
    p += 2;
  while (p < nbytes && code[p] == 0x90)
    ++p;
  *out_o = p;
  return p < nbytes;
}

// When the first real insn sequence is mov r10,rcx ; mov eax, imm32, that immediate is the SSN
// for this export. Take it before any strategy that walks other syscall sites in the same slice.
bool extract_ssn_mov_r10_b8_at_entry(const std::uint8_t* code, std::size_t nbytes, std::uint32_t* out) {
  if (!out)
    return false;
  std::size_t o = 0;
  if (!skip_export_prologue(code, nbytes, &o))
    return false;
  if (o + 8 > nbytes)
    return false;
  if (code[o] != 0x4C || code[o + 1] != 0x8B || code[o + 2] != 0xD1 || code[o + 3] != 0xB8)
    return false;
  std::uint32_t id = 0;
  std::memcpy(&id, code + o + 4, sizeof(id));
  if (!ssn_plausible(id))
    return false;
  const std::size_t after = o + 8;
  for (std::size_t t = after; t + 1 < nbytes && t <= after + k_max_gap_load_to_syscall; ++t) {
    if (code[t] == 0x0F && code[t + 1] == 0x05) {
      *out = id;
      return true;
    }
  }
  return false;
}

// Tied to the real entry of this export (after thunk): skips endbr/nop sled, then parses the
// canonical ntdll syscall prelude. This avoids pairing a stray earlier 0F 05 in the scan window.
bool try_prologue_ssn(const std::uint8_t* code, std::size_t nbytes, const std::uint8_t* mod_base,
                      std::size_t mod_size, std::uint32_t* out) {
  if (!out)
    return false;
  std::size_t o = 0;
  if (!skip_export_prologue(code, nbytes, &o))
    return false;

  if (o + 8 <= nbytes && code[o] == 0x4C && code[o + 1] == 0x8B && code[o + 2] == 0xD1 &&
      code[o + 3] == 0xB8) {
    std::uint32_t id = 0;
    std::memcpy(&id, code + o + 4, sizeof(id));
    if (!ssn_plausible(id))
      return false;
    const std::size_t after = o + 8;
    for (std::size_t t = after; t + 1 < nbytes && t <= after + k_max_gap_load_to_syscall; ++t) {
      if (code[t] == 0x0F && code[t + 1] == 0x05) {
        *out = id;
        return true;
      }
    }
  }

  if (o + 5 <= nbytes && code[o] == 0xB8) {
    std::uint32_t id = 0;
    std::memcpy(&id, code + o + 1, sizeof(id));
    if (!ssn_plausible(id))
      return false;
    const std::size_t after_b8 = o + 5;
    std::size_t after_r10 = 0;
    bool found_r10 = false;
    for (std::size_t t = after_b8; t + 3 < nbytes && t < o + 96; ++t) {
      if (code[t] == 0x4C && code[t + 1] == 0x8B && code[t + 2] == 0xD1) {
        after_r10 = t + 3;
        found_r10 = true;
        break;
      }
    }
    if (!found_r10)
      return false;
    for (std::size_t t = after_r10; t + 1 < nbytes && t <= after_r10 + k_max_gap_load_to_syscall;
         ++t) {
      if (code[t] == 0x0F && code[t + 1] == 0x05) {
        *out = id;
        return true;
      }
    }
  }

  if (o + 3 <= nbytes && code[o] == 0x4C && code[o + 1] == 0x8B && code[o + 2] == 0xD1) {
    const std::size_t j = o + 3;
    std::uint32_t id = 0;
    std::size_t load_end = 0;
    if (decode_mov_eax_rip(code, nbytes, j, mod_base, mod_size, &id, &load_end)) {
      for (std::size_t t = load_end; t + 1 < nbytes && t <= load_end + k_max_gap_load_to_syscall;
           ++t) {
        if (code[t] == 0x0F && code[t + 1] == 0x05) {
          *out = id;
          return true;
        }
      }
    }
  }

  return false;
}

bool try_forward_chain(const std::uint8_t* code, std::size_t nbytes, const std::uint8_t* mod_base,
                       std::size_t mod_size, std::uint32_t* out) {
  for (std::size_t i = 0; i + 3 < nbytes; ++i) {
    if (code[i] != 0x4C || code[i + 1] != 0x8B || code[i + 2] != 0xD1)
      continue;

    const std::size_t after_r10 = i + 3;
    const std::size_t win_end = (std::min)(nbytes, after_r10 + k_forward_r10_to_load_window);

    for (std::size_t k = after_r10; k < win_end; ++k) {
      std::uint32_t id = 0;
      std::size_t load_end = 0;

      if (k + 5 <= nbytes && code[k] == 0xB8) {
        std::memcpy(&id, code + k + 1, sizeof(id));
        load_end = k + 5;
      } else if (!decode_mov_eax_rip(code, nbytes, k, mod_base, mod_size, &id, &load_end)) {
        continue;
      }

      if (!ssn_plausible(id))
        continue;

      std::size_t syscall_pos = 0;
      bool found_syscall = false;
      for (std::size_t t = load_end; t + 1 < nbytes && t <= load_end + k_max_gap_load_to_syscall;
           ++t) {
        if (code[t] == 0x0F && code[t + 1] == 0x05) {
          syscall_pos = t;
          found_syscall = true;
          break;
        }
      }
      if (!found_syscall)
        continue;
      if (!stub_has_r10_for_load(code, nbytes, k, load_end, syscall_pos))
        continue;

      *out = id;
      return true;
    }
  }
  return false;
}

bool try_syscall_anchor(const std::uint8_t* code, std::size_t nbytes,
                        const std::uint8_t* mod_base, std::size_t mod_size, std::uint32_t* out) {
  std::size_t si = static_cast<std::size_t>(-1);
  for (std::size_t i = 0; i + 1 < nbytes; ++i) {
    if (code[i] == 0x0F && code[i + 1] == 0x05) {
      si = i;
      break;
    }
  }
  if (si == static_cast<std::size_t>(-1))
    return false;

  for (std::ptrdiff_t j = static_cast<std::ptrdiff_t>(si) - 1; j >= 0; --j) {
    const auto ju = static_cast<std::size_t>(j);

    if (ju + 5 <= si && code[ju] == 0xB8) {
      const std::size_t after = ju + 5;
      if (si - after > k_max_gap_load_to_syscall)
        continue;
      std::uint32_t id = 0;
      std::memcpy(&id, code + ju + 1, sizeof(id));
      if (!ssn_plausible(id))
        continue;
      if (!stub_has_r10_for_load(code, nbytes, ju, ju + 5, si))
        continue;
      *out = id;
      return true;
    }

    std::uint32_t id = 0;
    std::size_t load_end = 0;
    if (decode_mov_eax_rip(code, nbytes, ju, mod_base, mod_size, &id, &load_end)) {
      if (load_end <= si && si - load_end <= k_max_gap_load_to_syscall &&
          stub_has_r10_for_load(code, nbytes, ju, load_end, si)) {
        *out = id;
        return true;
      }
    }
  }
  return false;
}

}  // namespace

void* SyscallGate::follow_export_thunk(void* export_addr, int depth) {
  if (!export_addr || depth <= 0)
    return export_addr;

  auto* s = static_cast<const std::uint8_t*>(export_addr);

  if (s[0] == 0xEB) {
    const auto rel = static_cast<std::int8_t>(s[1]);
    return follow_export_thunk(const_cast<std::uint8_t*>(s + 2 + rel), depth - 1);
  }

  if (s[0] == 0xE9) {
    std::int32_t rel = 0;
    std::memcpy(&rel, s + 1, sizeof(rel));
    return follow_export_thunk(const_cast<std::uint8_t*>(s + 5 + rel), depth - 1);
  }

  if (s[0] == 0xFF && s[1] == 0x25) {
    std::int32_t disp = 0;
    std::memcpy(&disp, s + 2, sizeof(disp));
    const auto rip_after = reinterpret_cast<std::uintptr_t>(s + 6);
    const auto slot_addr = static_cast<std::uintptr_t>(
        static_cast<std::intptr_t>(rip_after) + static_cast<std::intptr_t>(disp));
    auto* slot = reinterpret_cast<void* const*>(slot_addr);
    if (!slot)
      return export_addr;
    void* target = *slot;
    if (!target)
      return export_addr;
    return follow_export_thunk(target, depth - 1);
  }

  return export_addr;
}

bool SyscallGate::scan_stub_for_ssn(const std::uint8_t* code, std::size_t nbytes,
                                    const std::uint8_t* mod_base, std::size_t mod_size,
                                    std::uint32_t* out_ssn) {
  if (!code || !out_ssn || !mod_base || nbytes < 24 || mod_size < 0x1000)
    return false;

  // 1) Export prologue: matches how ntdll actually starts this stub after thunk resolution.
  if (try_prologue_ssn(code, nbytes, mod_base, mod_size, out_ssn))
    return true;
  // 2) First syscall in the scan slice only (this export's syscall, not a later stray 0F 05).
  if (try_syscall_anchor(code, nbytes, mod_base, mod_size, out_ssn))
    return true;
  if (try_forward_chain(code, nbytes, mod_base, mod_size, out_ssn))
    return true;
  if (try_fastpath_contiguous(code, nbytes, out_ssn))
    return true;

  return false;
}

bool SyscallGate::resolve_export(HMODULE ntdll, void* export_addr, const char* export_name,
                                 std::uint32_t* out_ssn) {
  if (!ntdll || !export_addr || !out_ssn || !export_name) {
    std::snprintf(diag_, sizeof(diag_), "resolve_export: ntdll=%p export_addr=%p out_ssn=%p name=%s",
                  static_cast<void*>(ntdll), export_addr, static_cast<void*>(out_ssn),
                  export_name ? export_name : "(null)");
    return false;
  }
  *out_ssn = 0;

  MODULEINFO mi{};
  if (!GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi))) {
    const DWORD gle = GetLastError();
    std::snprintf(diag_, sizeof(diag_),
                  "GetModuleInformation(GetCurrentProcess(), ntdll=%p, &mi, %zu) returned 0; "
                  "GetLastError()=%lu (0x%08lX). export=%s",
                  static_cast<void*>(ntdll), sizeof(mi), static_cast<unsigned long>(gle),
                  static_cast<unsigned long>(gle), export_name);
    return false;
  }
  if (!mi.lpBaseOfDll || mi.SizeOfImage < 0x2000) {
    std::snprintf(diag_, sizeof(diag_),
                  "GetModuleInformation ok but lpBaseOfDll=%p SizeOfImage=0x%lX (export=%s)",
                  mi.lpBaseOfDll, static_cast<unsigned long>(mi.SizeOfImage), export_name);
    return false;
  }

  const auto* mod_base = static_cast<const std::uint8_t*>(mi.lpBaseOfDll);
  const auto mod_size = static_cast<std::size_t>(mi.SizeOfImage);

  void* p = follow_export_thunk(export_addr, 24);
  const auto* bytes = static_cast<const std::uint8_t*>(p);
  const auto base_u = reinterpret_cast<std::uintptr_t>(mod_base);
  const auto end_u = base_u + static_cast<std::uintptr_t>(mod_size);
  const auto cur_u = reinterpret_cast<std::uintptr_t>(bytes);
  if (cur_u < base_u || cur_u >= end_u) {
    std::snprintf(diag_, sizeof(diag_),
                  "export=%s: after thunk code VA=0x%llX outside ntdll [0x%llX .. 0x%llX) "
                  "(GetProcAddress gave %p, thunk target %p)",
                  export_name, static_cast<unsigned long long>(cur_u),
                  static_cast<unsigned long long>(base_u), static_cast<unsigned long long>(end_u),
                  export_addr, p);
    return false;
  }

  const std::size_t remain = static_cast<std::size_t>(end_u - cur_u);
  const std::size_t scan = (std::min)(k_export_scan_bytes, remain);
  if (scan < 32) {
    std::snprintf(diag_, sizeof(diag_),
                  "export=%s: stub scan window too small: remain=%zu cap=%zu -> scan=%zu (need >=32)",
                  export_name, remain, k_export_scan_bytes, scan);
    return false;
  }

  if (extract_ssn_mov_r10_b8_at_entry(bytes, scan, out_ssn)) {
    diag_[0] = '\0';
    return true;
  }

  if (!scan_stub_for_ssn(bytes, scan, mod_base, mod_size, out_ssn)) {
    char hex[3 * 24 + 8] = {};
    const std::size_t dump_n = (std::min)(scan, static_cast<std::size_t>(24));
    std::size_t hp = 0;
    for (std::size_t i = 0; i < dump_n && hp + 4 < sizeof(hex); ++i) {
      const int w =
          std::snprintf(hex + hp, sizeof(hex) - hp, "%02X%s", bytes[i], (i + 1 == dump_n) ? "" : " ");
      if (w <= 0)
        break;
      hp += static_cast<std::size_t>(w);
    }
    std::snprintf(diag_, sizeof(diag_),
                  "export=%s: SSN scan failed (prologue/anchor/forward/fastpath). "
                  "thunk_target=%p max_scan=%zu image_base=%p SizeOfImage=0x%zx leading_bytes[%zu]=%s",
                  export_name, p, scan, mi.lpBaseOfDll, mod_size, dump_n, hex);
    return false;
  }

  diag_[0] = '\0';
  return true;
}

// CFG bypass implementation using SetProcessValidCallTargets (Windows 10+)
namespace {

// CFG structures - define only if not already available
#ifndef CFG_CALL_TARGET_VALID
#define CFG_CALL_TARGET_VALID 0x00000001
#endif

// Custom CFG structure to avoid conflicts with SDK versions
struct SyscallCfgCallTargetInfo {
  ULONG_PTR Offset;
  ULONG_PTR Flags;
};

using SetProcessValidCallTargetsFn = BOOL(WINAPI*)(
    HANDLE hProcess,
    PVOID VirtualAddress,
    SIZE_T RegionSize,
    ULONG NumberOfOffsets,
    SyscallCfgCallTargetInfo* OffsetInformation);

SetProcessValidCallTargetsFn get_set_process_valid_call_targets() {
  static SetProcessValidCallTargetsFn fn = nullptr;
  static bool resolved = false;
  
  if (resolved)
    return fn;
  
  HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
  if (!kernelbase)
    kernelbase = GetModuleHandleW(L"kernel32.dll");
  
  if (kernelbase) {
    fn = reinterpret_cast<SetProcessValidCallTargetsFn>(
        GetProcAddress(kernelbase, "SetProcessValidCallTargets"));
  }
  
  resolved = true;
  return fn;
}

}  // namespace

SyscallGate::ExecutableMemory::~ExecutableMemory() {
  if (address) {
    VirtualFree(address, 0, MEM_RELEASE);
    address = nullptr;
  }
}

bool SyscallGate::ExecutableMemory::allocate(size_t requested_size) {
  if (address)
    return false;
  
  // Allocate as RW first, then change to RX after writing
  address = VirtualAlloc(nullptr, requested_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!address)
    return false;
  
  size = requested_size;
  return true;
}

bool SyscallGate::ExecutableMemory::register_cfg_target(void* target, size_t target_size) {
  if (!address || cfg_registered)
    return false;
  
  auto fn = get_set_process_valid_call_targets();
  if (!fn) {
    // CFG API not available (Windows 8.1 or older) - skip registration
    cfg_registered = true;
    return true;
  }
  
  // Use custom structure to avoid SDK conflicts
  SyscallCfgCallTargetInfo cfg_info = {};
  cfg_info.Offset = 0;
  cfg_info.Flags = CFG_CALL_TARGET_VALID;
  
  BOOL result = fn(
      GetCurrentProcess(),
      address,
      target_size,
      1,
      &cfg_info);
  
  if (result) {
    cfg_registered = true;
    return true;
  }
  
  // If registration fails, it might be because CFG is not enforced
  // Continue anyway - the syscall might still work
  cfg_registered = true;
  return true;
}

void* SyscallGate::make_gate_with_cfg(std::uint32_t ssn, std::unique_ptr<ExecutableMemory>& out_mem) {
  // Syscall stub: mov r10, rcx; mov eax, SSN; syscall; ret
  const std::uint8_t stub_template[] = {
      0x4C, 0x8B, 0xD1,              // mov r10, rcx
      0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, SSN (placeholder)
      0x0F, 0x05,                    // syscall
      0xC3,                          // ret
  };
  
  constexpr size_t stub_size = sizeof(stub_template);
  constexpr size_t page_size = 4096;
  
  auto mem = std::make_unique<ExecutableMemory>();
  if (!mem->allocate(page_size))
    return nullptr;
  
  // Patch SSN into template
  std::uint8_t stub[stub_size];
  std::memcpy(stub, stub_template, stub_size);
  std::memcpy(stub + 4, &ssn, sizeof(ssn));
  
  // Write stub to allocated memory
  std::memcpy(mem->address, stub, stub_size);
  
  // Register with CFG before making executable
  if (!mem->register_cfg_target(mem->address, stub_size)) {
    return nullptr;
  }
  
  // Change protection to RX
  DWORD old_protect = 0;
  if (!VirtualProtect(mem->address, page_size, PAGE_EXECUTE_READ, &old_protect)) {
    return nullptr;
  }
  
  // Flush instruction cache
  FlushInstructionCache(GetCurrentProcess(), mem->address, stub_size);
  
  void* gate = mem->address;
  out_mem = std::move(mem);
  return gate;
}

bool SyscallGate::init() {
  diag_[0] = '\0';

  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) {
    const DWORD gle = GetLastError();
    std::snprintf(diag_, sizeof(diag_),
                  "GetModuleHandleW(L\"ntdll.dll\") returned NULL; GetLastError()=%lu (0x%08lX)",
                  static_cast<unsigned long>(gle), static_cast<unsigned long>(gle));
    return false;
  }

  auto* p_read = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtReadVirtualMemory"));
  auto* p_write = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
  if (!p_read || !p_write) {
    const DWORD gle = GetLastError();
    std::snprintf(diag_, sizeof(diag_),
                  "GetProcAddress(ntdll=%p) NtReadVirtualMemory=%p NtWriteVirtualMemory=%p "
                  "GetLastError()=%lu (0x%08lX)",
                  static_cast<void*>(ntdll), p_read, p_write, static_cast<unsigned long>(gle),
                  static_cast<unsigned long>(gle));
    return false;
  }

  if (!resolve_export(ntdll, p_read, "NtReadVirtualMemory", &ssn_read_))
    return false;
  if (!resolve_export(ntdll, p_write, "NtWriteVirtualMemory", &ssn_write_))
    return false;

  read_gate_ = make_gate_with_cfg(ssn_read_, read_mem_);
  if (!read_gate_) {
    const DWORD gle = GetLastError();
    std::snprintf(diag_, sizeof(diag_),
                  "make_gate_with_cfg (read) failed; GetLastError()=%lu (0x%08lX); ssn_read_=0x%X",
                  static_cast<unsigned long>(gle), static_cast<unsigned long>(gle), ssn_read_);
    shutdown();
    return false;
  }
  
  write_gate_ = make_gate_with_cfg(ssn_write_, write_mem_);
  if (!write_gate_) {
    const DWORD gle = GetLastError();
    std::snprintf(diag_, sizeof(diag_),
                  "make_gate_with_cfg (write) failed; GetLastError()=%lu (0x%08lX); ssn_write_=0x%X",
                  static_cast<unsigned long>(gle), static_cast<unsigned long>(gle), ssn_write_);
    shutdown();
    return false;
  }

  p_read_ = reinterpret_cast<NtReadFn>(read_gate_);
  p_write_ = reinterpret_cast<NtWriteFn>(write_gate_);
  return true;
}

void SyscallGate::shutdown() {
  read_mem_.reset();
  write_mem_.reset();
  read_gate_ = nullptr;
  write_gate_ = nullptr;
  p_read_ = nullptr;
  p_write_ = nullptr;
  ssn_read_ = 0;
  ssn_write_ = 0;
  // Keep diag_ for caller inspection after failed init
}

NTSTATUS SyscallGate::read_mem(HANDLE proc, void* remote, void* local, size_t len, size_t* got) {
  SIZE_T n = 0;
  NTSTATUS st = p_read_(proc, remote, local, len, &n);
  if (got)
    *got = static_cast<size_t>(n);
  return st;
}

NTSTATUS SyscallGate::write_mem(HANDLE proc, void* remote, const void* local, size_t len,
                                size_t* wrote) {
  SIZE_T n = 0;
  NTSTATUS st =
      p_write_(proc, const_cast<PVOID>(remote), const_cast<PVOID>(local), len, &n);
  if (wrote)
    *wrote = static_cast<size_t>(n);
  return st;
}
