# winkrnl

A Windows kernel driver mapper using a vulnerable driver (IQVW64) for manual mapping into kernel space, with automatic trace cleanup.

> ⚠️ **For educational and research purposes only.** Requires administrator privileges and Windows 10/11 x64.

---

## Overview

winkrnl manually maps a kernel driver into memory without using the Windows driver loading infrastructure. It exploits the `iqvw64e.sys` (Intel Network Adapter Diagnostic Driver) to gain arbitrary kernel read/write primitives, maps the target driver, resolves its imports and relocations, calls its `DriverEntry`, then cleans up all traces of the vulnerable driver from kernel structures.

---

## Differences from kdmapper

[kdmapper](https://github.com/TheCruZ/kdmapper) is the most widely known open-source kernel mapper. winkrnl differs in several key areas:

### Architecture

| | winkrnl | kdmapper |
|---|---|---|
| Language standard | C++20 | C++17 |
| Driver abstraction | `BasicVulnDriver` base class | Monolithic, iqvw64-specific |
| Extensibility | Add new vuln drivers via inheritance | Requires rewrite |
| Logging | spdlog (leveled) | `std::cout` / `printf` |

### Driver abstraction layer

winkrnl introduces `BasicVulnDriver` — an abstract base class that decouples the mapper logic from the specific vulnerable driver being used. Adding support for a new vulnerable driver requires only implementing four virtual methods:

```cpp
virtual bool KeMemMove(uintptr_t dst, uintptr_t src, std::size_t size) const = 0;
virtual bool KeUnmapIoSpace(uintptr_t virtualAddr, std::size_t size) const = 0;
virtual uintptr_t KeMapIoSpace(uintptr_t physicalAddr, std::size_t size) const = 0;
virtual uintptr_t KeGetPhysicalAddress(uintptr_t virtualAddr) const = 0;
```

kdmapper hardcodes all IOCTL logic for iqvw64 directly into its mapping code.

### Kernel routine invocation

winkrnl uses a JMP hook on `NtAddAtom` (a rarely-used syscall) to invoke arbitrary kernel functions:

```
1. Resolve NtAddAtom address via export parser
2. Write: mov rax, <target>; jmp rax  (12 bytes)
3. Call NtAddAtom from user space — executes target kernel function
4. Restore original bytes
```

This approach allows calling any exported kernel function with arbitrary arguments via a single generic template:

```cpp
template <typename T, typename... A>
bool InvokeK32Routine(T* outResult, uintptr_t functionAddress, A... args);
```

kdmapper uses the same NtAddAtom technique but with a less generic implementation.

### Trace cleanup

winkrnl cleans up both kernel structures that record driver load history:

**PiDDBCacheList** — manually unlinks the entry by rewriting `Flink`/`Blink` pointers via kernel write primitives.

**PiDDBCacheTable** — uses `RtlLookupElementGenericTableAvl` to find the entry by `TimeDateStamp` + driver name, then removes it with `RtlDeleteElementGenericTableAvl`. This is the correct approach: it goes through the AVL tree's own comparator rather than manually walking tree nodes.

kdmapper also cleans both structures but walks the AVL tree manually, which is fragile across Windows versions.

**MmUnloadedDrivers** — the vulnerable driver is registered with a random 16-character name (generated at runtime via `GenerateRandomString`), which means `MiRememberUnloadedDriver` records an unrecognizable name. No additional cleanup of this structure is needed.

### Random driver name

```cpp
name(Utils::Common::GenerateRandomString(16))
```

The vulnerable driver is dropped to `%TEMP%\<random>.sys` on every run. This makes static detection by filename trivial to evade and avoids registry key collisions on repeated runs.

---

## Architecture

```
winkrnl
├── vuln/
│   ├── drivers/
│   │   ├── BasicVulnDriver      # Abstract base: IOCTL primitives
│   │   └── Iqvw64Driver         # IQVW64 implementation
│   ├── VulnDriverLoader         # Load/unload lifecycle + registry
│   └── VulnTraceCleaner         # PiDDBCacheList + PiDDBCacheTable cleanup
├── kernel/
│   ├── K32Module                # Kernel module base + export resolver
│   ├── K32ModuleParser          # Pattern scanning + RIP-relative resolution
│   └── K32Context               # Pool alloc/free + kernel routine invocation
├── mapper/
│   └── DriverMapper             # PE mapping: headers, sections, relocs, imports
└── utils/
    ├── pe_utils                 # NT headers, import/relocation parsing
    ├── fs_utils                 # File I/O
    └── cmn_utils                # Random string generation
```

---

## How it works

```
1.  Drop iqvw64e.sys to %TEMP%\<random>.sys
2.  Create registry entry under HKLM\...\Services\<random>
3.  NtLoadDriver → load vulnerable driver
4.  Open \\.\Nal device handle
5.  Parse ntoskrnl.exe exports via kernel read primitives
6.  Allocate NonPagedPool in kernel (ExAllocatePoolWithTag)
7.  Copy PE headers and sections to local buffer
8.  Resolve relocations (delta = kernelBase - ImageBase)
9.  Resolve imports (K32Module export lookup per dependency)
10. Write mapped image to kernel pool via WriteMappedMemory
        (virtual → physical → MmMapIoSpace → write → MmUnmapIoSpace)
11. Call DriverEntry(kernelBase, NULL) via NtAddAtom hook
12. Clean PiDDBCacheList  — unlink via Flink/Blink rewrite
13. Clean PiDDBCacheTable — RtlDeleteElementGenericTableAvl
14. NtUnloadDriver → unload iqvw64
15. Delete registry entry
16. Delete driver file from disk
```

---

## Requirements

- Windows 10/11 x64
- Administrator privileges
- `SeLoadDriverPrivilege` (enabled automatically)
- MSVC with C++20 (`/std:c++20`)
- [spdlog](https://github.com/gabime/spdlog)

---

## Usage

```
winkrnl.exe <driver_path>
```

```
winkrnl.exe C:\path\to\driver.sys
```

---

## Building

```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Or open the `.sln` in Visual Studio 2022 and build `x64 Release`.

---

## Disclaimer

This project is intended for **security research and educational purposes only**. Do not use on systems you do not own or have explicit permission to test. The authors take no responsibility for misuse.
