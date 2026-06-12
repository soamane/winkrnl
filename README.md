# winkrnl

A Windows kernel driver mapper using a vulnerable driver (IQVW64) for manual mapping into kernel space, with automatic trace cleanup.

> ⚠️ **For educational and research purposes only.** Requires administrator privileges and Windows 10/11 x64.

---

## Overview

winkrnl manually maps a kernel driver into memory without using the Windows driver loading infrastructure. It exploits `iqvw64e.sys` (Intel Network Adapter Diagnostic Driver) to gain arbitrary kernel read/write primitives, maps the target driver, resolves its imports and relocations, calls its `DriverEntry`, then cleans up all traces of the vulnerable driver from kernel structures.

---

## Differences from kdmapper

[kdmapper](https://github.com/TheCruZ/kdmapper) is the most widely known open-source kernel mapper. The core technique is the same — both use iqvw64 and the NtAddAtom hook. The difference is in how the code is written.

### kdmapper is a single translation unit

kdmapper is essentially one large file. All IOCTL logic, memory primitives, PE mapping, and trace cleanup are tangled together with no separation of concerns. Adding a new vulnerable driver means rewriting the core. Swapping out the trace cleanup strategy means touching the same file as the mapper.

winkrnl splits every concern into its own class with a clear responsibility:

```
vuln/drivers/BasicVulnDriver   — abstract kernel primitives (read, write, map, unmap)
vuln/drivers/Iqvw64Driver      — iqvw64-specific IOCTL implementation
vuln/VulnDriverLoader          — driver lifecycle: drop, load, unload, registry
vuln/VulnTraceCleaner          — PiDDBCacheList + PiDDBCacheTable cleanup
kernel/K32Module               — kernel module: base address, size, export resolver
kernel/K32ModuleParser         — pattern scanning, RIP-relative address resolution
kernel/K32Context              — pool alloc/free, kernel routine invocation
mapper/DriverMapper            — PE mapping: headers, sections, relocations, imports
utils/                         — pe_utils, fs_utils, cmn_utils
```

Each layer only knows about the layer below it. `DriverMapper` knows nothing about iqvw64. `VulnTraceCleaner` knows nothing about PE mapping. This is not how kdmapper is structured.

### Adding a new vulnerable driver

In kdmapper — fork and rewrite.

In winkrnl — inherit from `BasicVulnDriver` and implement four methods:

```cpp
virtual bool     KeMemMove(uintptr_t dst, uintptr_t src, std::size_t size) const = 0;
virtual bool     KeUnmapIoSpace(uintptr_t virtualAddr, std::size_t size) const = 0;
virtual uintptr_t KeMapIoSpace(uintptr_t physicalAddr, std::size_t size) const = 0;
virtual uintptr_t KeGetPhysicalAddress(uintptr_t virtualAddr) const = 0;
```

The rest of the codebase — mapper, trace cleaner, context — works unchanged.

### Generic kernel routine invocation

kdmapper hardcodes individual wrapper functions for each kernel call it needs. winkrnl exposes a single variadic template:

```cpp
template <typename T, typename... A>
bool InvokeK32Routine(T* outResult, uintptr_t functionAddress, A... args);
```

Any exported kernel function can be called with any signature. Adding `RtlLookupElementGenericTableAvl`, `RtlDeleteElementGenericTableAvl`, or `ExAllocatePoolWithTag` requires zero new plumbing — just pass the address and arguments.

### AVL tree cleanup

kdmapper walks the AVL tree nodes manually to find and remove the `PiDDBCacheTable` entry. This is fragile: it relies on the internal node layout staying consistent across Windows versions.

winkrnl calls the kernel's own AVL functions through the `InvokeK32Routine` hook:

```cpp
// Find entry using the table's own comparator
const auto entry = k32ctx->RtlLookupElementGenericTableAvl(table, &compared);

// Remove via the kernel's own balancing logic
k32ctx->RtlDeleteElementGenericTableAvl(table, entry);
```

This is the correct approach — the kernel handles node relinking and tree rebalancing internally.

### RAII throughout

kdmapper does manual cleanup with raw `if` chains. winkrnl uses RAII for every resource:

- `VulnDriverLoader` unloads the driver and deletes the file in its destructor
- `BasicVulnDriver` closes the device handle in its destructor  
- `VirtualAlloc` buffers are wrapped in `unique_ptr` with a custom deleter
- Registry entries and driver files are cleaned up as part of `Unload()`

No resource can leak without it being a bug in the destructor.

### C++20 and modern patterns

| | winkrnl | kdmapper |
|---|---|---|
| Standard | C++20 | C++17 |
| Logging | spdlog (trace/info/error levels) | `std::cout` / `printf` |
| Memory | `unique_ptr`, `shared_ptr`, RAII | Manual `delete` / `VirtualFree` |
| Null checks | `std::optional`, exceptions in constructors | Raw pointer checks |
| Compile-time checks | `static_assert` on all IOCTL struct offsets | None |

The `static_assert` on IOCTL structure offsets is worth calling out specifically — it catches padding issues at compile time rather than at runtime when the kernel silently does the wrong thing:

```cpp
static_assert(offsetof(CopyMemoryRequest, src)  == 0x10);
static_assert(offsetof(CopyMemoryRequest, dist) == 0x18);
static_assert(offsetof(CopyMemoryRequest, size) == 0x20);
```

### Random driver name

The vulnerable driver is dropped to `%TEMP%\<random16chars>.sys` on every run, generated at construction time:

```cpp
name(Utils::Common::GenerateRandomString(16))
```

`MiRememberUnloadedDriver` records this name in `MmUnloadedDrivers` — since it is unrecognizable and different on every run, no additional cleanup of that structure is needed.

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
10. Write mapped image to kernel via WriteMappedMemory
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

---

## Building

Open the `.sln` in Visual Studio 2022 and build `x64 Release`, or:

```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

---

## Disclaimer

This project is intended for **security research and educational purposes only**. Do not use on systems you do not own or have explicit permission to test. The authors take no responsibility for misuse.
