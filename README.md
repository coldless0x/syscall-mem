# syscall-mem

**Windows x64** research codebase that performs cross-process virtual memory read/write by invoking **`NtReadVirtualMemory`** and **`NtWriteVirtualMemory`** through **in-process syscall gates** (direct `syscall` instructions), instead of calling exported `ntdll` stubs. Syscall numbers (**SSNs**) are **derived at runtime** from the live `ntdll` image. The project is built to remain compatible with **Control Flow Guard (CFG)** when the binary is linked with **`/guard:cf`**, by registering dynamically allocated stub pages as **valid CFG call targets** via the documented **`SetProcessValidCallTargets`** API.

This repository is intended for **security research**, **operating-system internals education**, and **authorized testing** on systems you own or are explicitly permitted to analyze.

---

## Table of contents

- [What this project does](#what-this-project-does)
- [Why direct syscalls](#why-direct-syscalls)
- [Architecture](#architecture)
- [Resolving syscall numbers from ntdll](#resolving-syscall-numbers-from-ntdll)
- [Syscall gate and machine code](#syscall-gate-and-machine-code)
- [Control Flow Guard (CFG) integration](#control-flow-guard-cfg-integration)
- [API surface (`SyscallGate`)](#api-surface-syscallgate)
- [Reference harness (`debug.cpp`)](#reference-harness-debugcpp)
- [Build and run](#build-and-run)
- [Limitations and operational reality](#limitations-and-operational-reality)
- [Repository layout](#repository-layout)
- [License and responsible use](#license-and-responsible-use)

---

## What this project does

1. **Locates** the in-memory `ntdll.dll` stubs for `NtReadVirtualMemory` and `NtWriteVirtualMemory`.
2. **Follows** common export indirections (short jumps `EB`, relative jumps `E9`, RIP-relative thunks `FF 25`, within a bounded recursion depth).
3. **Extracts** the correct **system service number** for each routine from the stub’s **x86-64 instruction stream**, using several complementary decoding strategies (see below).
4. **Allocates** private executable memory, **writes** minimal syscall trampolines, **registers** them with the OS CFG machinery where available, **transitions** the page from read-write to **execute-read**, and **flushes** the instruction cache.
5. **Exposes** thin wrappers that call those gates with the same calling convention as the native `ntdll` exports, returning **`NTSTATUS`** and optional **byte counts** (`PSIZE_T`).

The included **`debug.cpp`** program demonstrates end-to-end behavior: process discovery (`notepad.exe` with fallback to self), `OpenProcess` with appropriate access rights, `VirtualAllocEx`, read/write probes, and detailed logging (`NTSTATUS`, `GetLastError`, `FormatMessage`, `memcmp` context).

---

## Why direct syscalls

User-mode code that calls `Nt*` through `ntdll` passes through the **official** user–kernel boundary implemented by Microsoft. In research and defensive contexts, it is useful to understand:

- How **SSNs** are encoded in stubs and how they **change across OS builds**.
- How **indirect branch protection (CFG)** interacts with **dynamically generated code** that is invoked like a function pointer.
- How security products may instrument or replace `ntdll` paths while the **syscall instruction** path remains a distinct control-flow and telemetry surface.

This code does **not** claim to be stealthy or “undetectable”; it is a **clear, instrumentable** reference implementation.

---

## Architecture

At a high level:

```text
  Application
       │
       ▼
  SyscallGate::init()
       │── resolve_export() × 2  (SSN from ntdll)
       │── make_gate_with_cfg() × 2  (RW → CFG register → RX)
       ▼
  read_mem / write_mem
       │── indirect call → gate stub → syscall → kernel
       ▼
  NtReadVirtualMemory / NtWriteVirtualMemory completion
```

Resource management uses **RAII** (`std::unique_ptr<ExecutableMemory>`): gate memory is released on `shutdown()` or destructor.

---

## Resolving syscall numbers from ntdll

Modern `ntdll` builds vary: instruction order (`mov r10, rcx` vs immediate load), use of **`mov eax, imm32`** vs **`mov eax, dword ptr [rip+disp32]`** against a data table, prologue padding (`endbr64`, `nop` sleds), and export thunks. The resolver therefore:

| Stage | Role |
|--------|------|
| **`follow_export_thunk`** | Normalizes the pointer returned by `GetProcAddress` through `EB` / `E9` / `FF 25` chains (depth-limited). |
| **`GetModuleInformation` (Psapi)** | Obtains the module base and **`SizeOfImage`** so RIP-relative loads and all reads stay within the mapped image. |
| **`extract_ssn_mov_r10_b8_at_entry`** | Fast path when the canonical sequence appears right after the skipped export prologue. |
| **`try_prologue_ssn`** | Parses the canonical prelude at the real entry: contiguous `r10`/`eax` patterns, **`B8`** before **`mov r10`**, or **`mov eax`** from **`[rip+disp]`** with a following **`syscall`**. |
| **`try_syscall_anchor`** | Anchors on the **first** `syscall` in the scan window and walks backward for the associated load of **`eax`**, requiring a consistent **`mov r10, rcx`** relationship. |
| **`try_forward_chain`** | Scans forward from each **`mov r10, rcx`** for a plausible load + `syscall` pair within bounded windows. |
| **`try_fastpath_contiguous`** | Detects a tight `4C 8B D1 B8` … `0F 05` layout. |

**Plausibility checks** reject obviously invalid immediates (e.g. zero, unreasonably large values for an SSN). On failure, **`diagnostic()`** contains a compact **hex snapshot** of leading bytes and addresses to simplify diffing across builds.

---

## Syscall gate and machine code

Each gate is a **12-byte** stub (then padded to a full page allocation):

```asm
mov r10, rcx          ; Windows x64 syscall convention: first argument in r10
mov eax, <ssn>       ; system service number
syscall               ; enter kernel
ret                   ; return to caller
```

The gate is **`NtAPI`-compatible** for these two routines: the caller passes **`HANDLE`**, **`PVOID`**, **`PVOID`**, **`SIZE_T`**, **`PSIZE_T`** as for the real exports.

---

## Control Flow Guard (CFG) integration

When **Control Flow Guard** is enabled (MSVC **`/guard:cf`**), the loader and runtime track **valid indirect call targets**. A freshly allocated page containing a `ret` target is **not** automatically valid; an indirect call through a function pointer to that address can **fail fast** (process termination) if the address is not marked as a permitted target.

This project uses **`SetProcessValidCallTargets`** (resolved via **`GetProcAddress`** on `kernelbase.dll` / `kernel32.dll`), which is the **supported** mechanism to declare that a region of memory contains **valid call targets** at specified offsets. The implementation:

1. Allocates memory as **`PAGE_READWRITE`**.
2. Copies the stub bytes.
3. Calls **`SetProcessValidCallTargets`** for the **current process**, marking offset **0** with **`CFG_CALL_TARGET_VALID`** (structure layout compatible with **`CFG_CALL_TARGET_INFO`**).
4. Applies **`VirtualProtect`** → **`PAGE_EXECUTE_READ`** (no write+execute in the steady state).
5. Calls **`FlushInstructionCache`**.

The Visual Studio project links **x64 Debug/Release** with **`<ControlFlowGuard>true</ControlFlowGuard>`** so this path is exercised under the same constraints as a typical hardened binary.

If the API is **absent** (older OS) or returns **FALSE**, the code **records** the outcome in logic but **does not abort initialization solely for that reason**—behavior then depends on whether CFG is actually enforced for the process.

**Terminology:** this is **CFG compatibility** using a **public OS API**, not an exploit against the kernel or a “CFG vulnerability.”

---

## API surface (`SyscallGate`)

| Method | Description |
|--------|-------------|
| **`bool init()`** | Builds read/write gates; on failure, see **`diagnostic()`**. |
| **`void shutdown()`** | Frees gate memory and clears function pointers. |
| **`NTSTATUS read_mem(...)`** | `NtReadVirtualMemory`-compatible direct syscall. |
| **`NTSTATUS write_mem(...)`** | `NtWriteVirtualMemory`-compatible direct syscall. |
| **`ssn_read()` / `ssn_write()`** | Resolved SSNs (for logging or research). |
| **`diagnostic()`** | Null-terminated ASCII detail buffer after failed **`init()`**. |

Header: **`syscall-mem/include/syscall_gate.hpp`**.

Additional examples: **`syscall-mem/USAGE.md`**.

---

## Reference harness (`debug.cpp`)

The console harness (build entry point) provides:

- **`[+] / [-]`** structured logging.
- **`FormatMessage`**-backed Win32 error strings.
- **`NTSTATUS`** reporting with **`NT_SUCCESS`** context.
- Optional **worker-thread read probe** with **`WaitForSingleObject`** timeout messaging.
- **`memcmp`**-style verification with **first-difference** diagnostics.

`main.cpp` remains in the project but is **excluded from the build** in favor of **`debug.cpp`**.

---

## Build and run

**Requirements**

- Windows **10 or later** recommended (CFG registration path matches the implementation assumptions).
- **Visual Studio 2019+** with **Desktop development with C++** and a recent **Windows 10/11 SDK**.
- **x64 only** (Win32 configurations are not supported for the syscall gate).

**Steps**

1. Open **`syscall-mem.sln`**.
2. Select **x64** and **Debug** or **Release**.
3. Build the solution.

**Run**

1. Optionally start **`notepad.exe`** for cross-process testing.
2. Execute the built **`syscall-mem.exe`** from the output directory (e.g. **`x64\Release`**).
3. Confirm **`[+]`** lines for gate initialization, target selection, allocation, read/write, and verify.

---

## Limitations and operational reality

- **SSN scanning** can fail or mis-parse on **heavily modified** `ntdll` images (hooks, shims, or non-standard stubs). The diagnostics are meant to help compare **expected vs observed** bytes.
- **Direct syscalls** are a well-known telemetry and policy surface for **EDR** and **kernel callbacks**; this code is for **controlled** environments.
- **CET / shadow stacks**, **HVCI**, **kernel PatchGuard**, and **driver-based monitoring** are outside the scope of this user-mode sample but may affect what you observe on a given machine.
- Successful virtual-memory operations still require **appropriate handle rights** (`PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, etc.) and **kernel enforcement** (integrity, sandboxing, protected processes).

---

## Repository layout

```text
syscall-mem/
├── syscall-mem.sln
├── syscall-mem/
│   ├── syscall-mem.vcxproj
│   ├── include/
│   │   └── syscall_gate.hpp
│   └── src/
│       ├── syscall_gate.cpp   # SSN resolution, gates, CFG registration
│       ├── debug.cpp          # Reference console harness (entry point)
│       └── main.cpp           # Excluded from build (optional minimal main)
├── USAGE.md                   # API usage examples
├── publish-github.ps1         # Optional helper to init/commit/push
└── README.md
```

---

## License and responsible use

See **`LICENSE`** in this repository. Use this software **only** on systems you **own** or where you have **explicit written authorization**. The authors disclaim responsibility for misuse. Understanding user–kernel interfaces and mitigations is part of defensive security; weaponizing this against third parties without consent is **unethical** and often **illegal**.

---

## Acknowledgement

Windows, `ntdll`, and related names are trademarks of Microsoft Corporation. This project is **not affiliated with** or endorsed by Microsoft.
