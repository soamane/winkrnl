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

## Example Output

```
winkrnl.exe driver.sys
[info] Module 'ntoskrnl.exe' initialized: base=0xFFFFF80482A00000, size=0x1450000
[info] SizeOfImage: 0x7000, SizeOfSections: 0x6000
[info] Export 'ExAllocatePoolWithTag' found at 0xFFFFF80483573010
[info] Export 'NtAddAtom' found at 0xFFFFF804831C19B0
[info] Kernel memory allocated at: 0xFFFFE601349C4000
[info] Processed 1 relocation blocks
[info] Import: ntoskrnl.exe
[info] Module 'ntoskrnl.exe' initialized: base=0xFFFFF80482A00000, size=0x1450000
[info] Export 'DbgPrintEx' found at 0xFFFFF80482C060E0
[info]     DbgPrintEx -> 0xFFFFF80482C060E0
[info] Imports resolved
[info] Image written to kernel
[info] Calling DriverEntry at 0xFFFFE601349C5000
[info] Cache hit for export 'NtAddAtom': 0xFFFFF804831C19B0
[info] DriverEntry returned: 0x0
[info] Driver loaded at 0xFFFFE601349C4000
[info] Export 'RtlLookupElementGenericTableAvl' found at 0xFFFFF80482DF92F0
[info] Cache hit for export 'NtAddAtom': 0xFFFFF804831C19B0
[info] Export 'RtlDeleteElementGenericTableAvl' found at 0xFFFFF80482DE9600
[info] Cache hit for export 'NtAddAtom': 0xFFFFF804831C19B0
[info] Program has successfully completed its execution
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
