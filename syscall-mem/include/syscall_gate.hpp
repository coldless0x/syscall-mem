#pragma once

#include <Windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <memory>

#if !defined(_M_X64)
#error Direct syscall gates are for Windows x64 only. Switch platform to x64.
#endif

/// @brief Professional syscall gate implementation with CFG bypass support
/// @details Resolves syscall numbers from ntdll stubs and creates direct syscall trampolines
///          with proper CFG validation for Windows 10+ compatibility
class SyscallGate {
public:
  SyscallGate() = default;
  ~SyscallGate() { shutdown(); }

  SyscallGate(const SyscallGate&) = delete;
  SyscallGate& operator=(const SyscallGate&) = delete;

  /// @brief Initialize syscall gates with CFG bypass
  /// @return true on success, false on failure (check diagnostic() for details)
  bool init();

  /// @brief Clean up allocated resources
  void shutdown();

  /// @brief Read memory from target process via direct syscall
  /// @param proc Target process handle
  /// @param remote Remote address to read from
  /// @param local Local buffer to read into
  /// @param len Number of bytes to read
  /// @param got Output: actual bytes read (can be nullptr)
  /// @return NTSTATUS code
  NTSTATUS read_mem(HANDLE proc, void* remote, void* local, size_t len, size_t* got);

  /// @brief Write memory to target process via direct syscall
  /// @param proc Target process handle
  /// @param remote Remote address to write to
  /// @param local Local buffer to write from
  /// @param len Number of bytes to write
  /// @param wrote Output: actual bytes written (can be nullptr)
  /// @return NTSTATUS code
  NTSTATUS write_mem(HANDLE proc, void* remote, const void* local, size_t len, size_t* wrote);

  std::uint32_t ssn_read() const { return ssn_read_; }
  std::uint32_t ssn_write() const { return ssn_write_; }
  const char* diagnostic() const { return diag_; }

private:
  using NtReadFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
  using NtWriteFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

  /// @brief CFG-aware memory allocator for executable code
  struct ExecutableMemory {
    void* address = nullptr;
    size_t size = 0;
    bool cfg_registered = false;

    ~ExecutableMemory();
    bool allocate(size_t requested_size);
    bool register_cfg_target(void* target, size_t target_size);
  };

  static void* follow_export_thunk(void* export_addr, int depth);
  static bool scan_stub_for_ssn(const std::uint8_t* code, std::size_t nbytes,
                                const std::uint8_t* mod_base, std::size_t mod_size,
                                std::uint32_t* out_ssn);
  bool resolve_export(HMODULE ntdll, void* export_addr, const char* export_name,
                      std::uint32_t* out_ssn);
  
  /// @brief Create syscall gate with CFG bypass
  /// @param ssn Syscall number
  /// @param out_mem Output: ExecutableMemory object managing the allocation
  /// @return Pointer to executable gate, or nullptr on failure
  void* make_gate_with_cfg(std::uint32_t ssn, std::unique_ptr<ExecutableMemory>& out_mem);

  std::unique_ptr<ExecutableMemory> read_mem_;
  std::unique_ptr<ExecutableMemory> write_mem_;
  void* read_gate_ = nullptr;
  void* write_gate_ = nullptr;
  NtReadFn p_read_ = nullptr;
  NtWriteFn p_write_ = nullptr;
  std::uint32_t ssn_read_ = 0;
  std::uint32_t ssn_write_ = 0;
  char diag_[768] = {};
};
