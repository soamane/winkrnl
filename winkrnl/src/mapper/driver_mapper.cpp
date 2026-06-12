#include "driver_mapper.hpp"

#include <kernel/k32_context.hpp>
#include <kernel/k32_module.hpp>
#include <spdlog/spdlog.h>

DriverMapper::DriverMapper(std::shared_ptr<K32Context> k32ctx, std::shared_ptr<K32Module> k32Module)
    : k32ctx(std::move(k32ctx))
    , k32Module(std::move(k32Module))
{
}

bool DriverMapper::Map(void* fileBytes)
{
    PIMAGE_NT_HEADERS ntHeaders = Utils::PE::GetNtHeaders(fileBytes);
    if (!ntHeaders) {
        spdlog::error("Failed to fetch image NT headers");
        return false;
    }

    PVOID imageBaseAddr = VirtualAlloc(nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!imageBaseAddr) {
        spdlog::error("Failed to alloc memory for image");
        return false;
    }

    const auto imageSize = ntHeaders->OptionalHeader.SizeOfImage - IMAGE_FIRST_SECTION(ntHeaders)->VirtualAddress;
    spdlog::info("SizeOfImage: 0x{:X}, SizeOfSections: 0x{:X}", ntHeaders->OptionalHeader.SizeOfImage, imageSize);

    uintptr_t kernelBaseAddr = k32ctx->AllocatePool(POOL_TYPE::NonPagedPool, imageSize);
    if (!kernelBaseAddr) {
        spdlog::error("Failed to allocate kernel memory");
        VirtualFree(imageBaseAddr, 0, MEM_RELEASE);
        return false;
    }

    spdlog::info("Kernel memory allocated at: 0x{:016X}", kernelBaseAddr);

    CopyToMemory(reinterpret_cast<uintptr_t>(imageBaseAddr), ntHeaders, fileBytes);

    auto relocs = Utils::PE::GetRelocations(imageBaseAddr, ntHeaders);
    ResolveRelocations(kernelBaseAddr - ntHeaders->OptionalHeader.ImageBase, ntHeaders, relocs);

    if (!ResolveImports(Utils::PE::GetImports(imageBaseAddr, ntHeaders))) {
        spdlog::error("Failed to resolve imports");
        VirtualFree(imageBaseAddr, 0, MEM_RELEASE);
        k32ctx->FreePool(kernelBaseAddr);
        return false;
    }

    spdlog::info("Imports resolved");

    const auto& driver = k32ctx->GetDriver();
    if (!driver.WriteMemory(kernelBaseAddr, imageBaseAddr, imageSize)) {
        spdlog::error("Failed to write image to kernel");
        VirtualFree(imageBaseAddr, 0, MEM_RELEASE);
        k32ctx->FreePool(kernelBaseAddr);
        return false;
    }

    spdlog::info("Image written to kernel");

    uintptr_t entryPointAddr = kernelBaseAddr + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    spdlog::info("Calling DriverEntry at 0x{:016X}", entryPointAddr);

    NTSTATUS status;
    if (!k32ctx->InvokeK32Routine(&status, entryPointAddr, kernelBaseAddr)) {
        spdlog::error("Failed to call DriverEntry");
        VirtualFree(imageBaseAddr, 0, MEM_RELEASE);
        return false;
    }

    spdlog::info("DriverEntry returned: 0x{:X}", static_cast<ULONG>(status));
    spdlog::info("Driver loaded at 0x{:016X}", kernelBaseAddr);

    VirtualFree(imageBaseAddr, 0, MEM_RELEASE);
    return true;
}

void DriverMapper::CopyToMemory(uintptr_t baseAddress, PIMAGE_NT_HEADERS ntHeaders, void* data)
{
    std::memcpy(reinterpret_cast<void*>(baseAddress), data, ntHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {

        if (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            continue;
        }

        if (sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData > ntHeaders->OptionalHeader.SizeOfImage) {
            continue;
        }

        PVOID section = reinterpret_cast<void*>(baseAddress + sectionHeader[i].VirtualAddress);
        std::memcpy(section, reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + sectionHeader[i].PointerToRawData), sectionHeader[i].SizeOfRawData);
    }
}

bool DriverMapper::ResolveImports(const std::vector<Utils::PE::Import>& imports)
{
    for (const auto& import : imports) {
        const auto currentModule = K32Module(k32ctx->GetDriver(), import.name);

        for (auto& thunk : import.thunks) {
            auto functionAddress = currentModule.GetK32ExportProcAddress(thunk.name);
            if (!functionAddress) {
                spdlog::error("Failed to resolve: {}!{}", import.name, thunk.name);
                return false;
            }

            *thunk.address = functionAddress;
            spdlog::info("    {} -> 0x{:016X}", thunk.name, functionAddress);
        }
    }

    return true;
}

void DriverMapper::ResolveRelocations(uintptr_t baseAddress, PIMAGE_NT_HEADERS ntHeaders, const std::vector<Utils::PE::Relocation>& relocs)
{
    ULONG_PTR delta = baseAddress - ntHeaders->OptionalHeader.ImageBase;

    for (const auto& reloc : relocs) {
        for (WORD i = 0; i < reloc.countOfEntries; ++i) {
            const auto type = reloc.infoPtr[i] >> 12;
            const auto offset = reloc.infoPtr[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                *reinterpret_cast<uintptr_t*>(reloc.address + offset) += delta;
            }
        }
    }
}