#include "pe_utils.hpp"

#include <print>

PIMAGE_NT_HEADERS Utils::PE::GetNtHeaders(void* image)
{
    if (!image) {
        std::println("[-] Image is nullptr");
        return nullptr;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::println("[-] Invalid DOS signature");
        return nullptr;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(image) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::println("[-] Invalid NT signature");
        return nullptr;
    }

    return ntHeaders;
}

std::vector<Utils::PE::Import> Utils::PE::GetImports(void* image, PIMAGE_NT_HEADERS ntHeaders)
{
    const auto pImage = reinterpret_cast<uintptr_t>(image);

    const auto importsDirAddr = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    auto importsDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImage + importsDirAddr);

    std::vector<Import> imports;
    while (importsDescriptor->FirstThunk) {
        Import i;
        i.name = std::string(reinterpret_cast<char*>(pImage + importsDescriptor->Name));

        std::println("[+] Import: {}", i.name);

        auto firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pImage + importsDescriptor->FirstThunk);
        auto originFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pImage + importsDescriptor->OriginalFirstThunk);

        while (originFirstThunk->u1.Function) {
            const auto thunkInfo = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pImage + originFirstThunk->u1.AddressOfData);

            Import::Thunk thunk;
            thunk.name = thunkInfo->Name;
            thunk.address = &firstThunk->u1.Function;

            i.thunks.push_back(thunk);

            ++firstThunk;
            ++originFirstThunk;
        }

        imports.push_back(i);
        ++importsDescriptor;
    }

    return imports;
}

std::vector<Utils::PE::Relocation> Utils::PE::GetRelocations(void* image, PIMAGE_NT_HEADERS ntHeaders)
{
    const auto relocsBase = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const auto relocsSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    std::vector<Relocation> relocs;

    auto currReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(image) + relocsBase);
    const auto end = reinterpret_cast<uintptr_t>(currReloc) + relocsSize;

    while (currReloc->VirtualAddress && currReloc->SizeOfBlock != 0) {
        Relocation reloc;
        reloc.address = reinterpret_cast<uintptr_t>(image) + currReloc->VirtualAddress;
        reloc.infoPtr = reinterpret_cast<WORD*>(currReloc + 1);
        reloc.countOfEntries = (currReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        relocs.push_back(reloc);
        currReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(currReloc) + currReloc->SizeOfBlock);
    }

    std::println("[+] Processed {} relocation blocks", relocs.size());
    return relocs;
}
