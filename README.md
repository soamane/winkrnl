# winkrnl

A Windows kernel driver mapper with a driver-agnostic architecture — bring your own vulnerable driver by implementing a simple interface.

> ⚠️ **For educational and research purposes only.** Requires administrator privileges and Windows 10/11 x64.

---

## Overview

winkrnl manually maps a kernel driver into memory without using the Windows driver loading infrastructure. It uses a vulnerable driver to gain arbitrary kernel read/write primitives, maps the target driver, resolves its imports and relocations, calls its `DriverEntry`, then cleans up all traces of the vulnerable driver from kernel structures.

The core design principle: **the vulnerable driver is a plugin, not a dependency.** The mapper, trace cleaner, and kernel context have zero knowledge of which driver is providing the primitives.

---

## Adding Your Own Vulnerable Driver

Any driver that exposes IOCTL-based kernel read/write/map can be integrated. Inherit from `BasicVulnDriver` and implement four methods:

```cpp
class MyVulnDriver : public BasicVulnDriver {
    bool      KeMemMove(uintptr_t dst, uintptr_t src, std::size_t size) const override;
    bool      KeUnmapIoSpace(uintptr_t virtualAddr, std::size_t size) const override;
    uintptr_t KeMapIoSpace(uintptr_t physicalAddr, std::size_t size) const override;
    uintptr_t KeGetPhysicalAddress(uintptr_t virtualAddr) const override;
};
```

Each method maps directly to one IOCTL call to your driver. The rest of the codebase — mapper, trace cleaner, kernel context — works unchanged. No other files need to be touched.

The bundled `Iqvw64Driver` is just one implementation of this interface, included as a reference.

---

## Architecture

```
vuln/drivers/BasicVulnDriver   — abstract kernel primitives (read, write, map, unmap)
vuln/drivers/Iqvw64Driver      — reference implementation using iqvw64e.sys
vuln/VulnDriverLoader          — driver lifecycle: drop, load, unload, registry
vuln/VulnTraceCleaner          — PiDDBCacheList + PiDDBCacheTable + PsLoadedModuleList cleanup
kernel/K32Module               — kernel module: base address, size, export resolver
kernel/K32ModuleParser         — pattern scanning, RIP-relative address resolution
kernel/K32Context              — pool alloc/free, kernel routine invocation
mapper/DriverMapper            — PE mapping: headers, sections, relocations, imports
utils/                         — pe_utils, fs_utils, cmn_utils
```

Each layer only knows about the layer below it. `DriverMapper` knows nothing about which vulnerable driver is in use. `VulnTraceCleaner` knows nothing about PE mapping.

---

## Differences from kdmapper

[kdmapper](https://github.com/TheCruZ/kdmapper) is the most widely known open-source kernel mapper. The core technique is similar. The difference is in architecture and extensibility.

### kdmapper is tied to a single driver

kdmapper is essentially one large file. All IOCTL logic, memory primitives, PE mapping, and trace cleanup are tangled together. Swapping the vulnerable driver means rewriting the core.

winkrnl treats the vulnerable driver as a plugin. Every IOCTL interaction is encapsulated behind `BasicVulnDriver`. Replacing the driver is a matter of writing one new class.

### Generic kernel routine invocation

kdmapper hardcodes individual wrapper functions for each kernel call it needs. winkrnl exposes a single variadic template:

```cpp
template <typename T, typename... A>
bool InvokeK32Routine(T* outResult, uintptr_t functionAddress, A... args);
```

Any exported kernel function can be called with any signature. Adding `RtlLookupElementGenericTableAvl`, `RtlDeleteElementGenericTableAvl`, or `ExAllocatePoolWithTag` requires zero new plumbing.

### AVL tree cleanup

Both kdmapper and winkrnl call the kernel's own AVL functions to remove the `PiDDBCacheTable` entry. The difference is in how those calls are made.

kdmapper has individual hardcoded wrapper functions for each kernel routine it needs. winkrnl uses a single variadic template that works for any kernel function:

```cpp
const auto entry = k32ctx->RtlLookupElementGenericTableAvl(table, &compared);
k32ctx->RtlDeleteElementGenericTableAvl(table, entry);
```

Adding a new kernel call in winkrnl requires no new plumbing — pass the address and arguments, the template handles the rest.

### PsLoadedModuleList cleanup

winkrnl walks `PsLoadedModuleList` and zeroes `BaseDllName` in the driver's `LDR_DATA_TABLE_ENTRY` before unloading. When the kernel calls `MiRememberUnloadedDriver` during unload, it checks `Name.Length > 0` before recording the entry — an empty name means the driver is never written to `MmUnloadedDrivers`.

### RAII throughout

kdmapper does manual cleanup with raw `if` chains. winkrnl uses RAII for every resource:

- `VulnDriverLoader` unloads the driver and deletes the file in its destructor
- `BasicVulnDriver` closes the device handle in its destructor
- `VirtualAlloc` buffers are wrapped in `unique_ptr` with a custom deleter
- Registry entries and driver files are cleaned up as part of `Unload()`

### C++20 and modern patterns

| | winkrnl | kdmapper |
|---|---|---|
| Standard | C++20 | C++17 |
| Logging | spdlog (trace/info/error) | `std::cout` / `printf` |
| Memory | `unique_ptr`, `shared_ptr`, RAII | Manual `delete` / `VirtualFree` |
| Null checks | `std::optional`, constructor exceptions | Raw pointer checks |
| Compile-time checks | `static_assert` on all IOCTL struct offsets | None |

The `static_assert` on IOCTL structure offsets catches padding issues at compile time rather than at runtime:

```cpp
static_assert(offsetof(CopyMemoryRequest, src)  == 0x10);
static_assert(offsetof(CopyMemoryRequest, dist) == 0x18);
static_assert(offsetof(CopyMemoryRequest, size) == 0x20);
```

---

## Trace Cleanup

winkrnl cleans three kernel structures after mapping:

**PiDDBCacheList** — doubly linked list of previously loaded drivers. The entry matching the vulnerable driver's timestamp is unlinked by rewriting `Flink`/`Blink` of its neighbors.

**PiDDBCacheTable** — AVL tree indexed by the same data. The entry is removed by calling `RtlDeleteElementGenericTableAvl` through the kernel routine hook.

**PsLoadedModuleList** — loaded module list. `BaseDllName.Length` is zeroed before unload so `MiRememberUnloadedDriver` skips recording the driver in `MmUnloadedDrivers`.

---

## How It Works

```
1.  Drop vulnerable driver to %TEMP%\<random16chars>.sys
2.  Create registry entry under HKLM\...\Services\<random>
3.  NtLoadDriver → load vulnerable driver
4.  Open device handle
5.  Parse ntoskrnl.exe exports via kernel read primitives
6.  Allocate NonPagedPool in kernel (ExAllocatePoolWithTag)
7.  Copy PE headers and sections to local buffer
8.  Resolve relocations (delta = kernelBase - ImageBase)
9.  Resolve imports (K32Module export lookup per dependency)
10. Write mapped image to kernel via WriteMappedMemory
        (virtual → physical → MmMapIoSpace → write → MmUnmapIoSpace)
11. Call DriverEntry(kernelBase, NULL) via NtAddAtom hook
12. Zero BaseDllName in PsLoadedModuleList
13. Clean PiDDBCacheList  — unlink via Flink/Blink rewrite
14. Clean PiDDBCacheTable — RtlDeleteElementGenericTableAvl
15. NtUnloadDriver → unload vulnerable driver
16. Delete registry entry
17. Delete driver file from disk
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
