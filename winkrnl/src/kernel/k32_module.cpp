#include "k32_module.hpp"

#include <vuln/drivers/basic_vuln_driver.hpp>

#include <DbgHelp.h>
#include <psapi.h>

K32Module::K32Module(const BasicVulnDriver& driver, std::string_view moduleName)
    : driver(std::move(driver))
    , moduleName(moduleName)
    , moduleSize(0)
    , moduleBase(0)
{
    if (!InitModuleInfo()) {
        throw std::runtime_error("Failed to initialize module info");
    }
}

std::size_t K32Module::GetK32ModuleSize() const
{
    return moduleSize;
}

std::string K32Module::GetK32ModuleName() const
{
    return moduleName;
}

uintptr_t K32Module::GetK32ModuleBaseAddress() const
{
    return moduleBase;
}

uintptr_t K32Module::GetK32ExportProcAddress(std::string_view funcName) const
{
    if (auto it = foundExports.find(funcName.data()); it != foundExports.end()) {
        return it->second;
    }

    IMAGE_DOS_HEADER dosHeader { };
    if (!driver.ReadMemory(moduleBase, &dosHeader, sizeof(dosHeader)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::println("[-] Invalid DOS header");
        return 0;
    }

    IMAGE_NT_HEADERS64 ntHeaders { };
    if (!driver.ReadMemory(moduleBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders)) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::println("[-] Invalid NT headers");
        return 0;
    }

    const auto& exportDataDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const auto exDirSize = exportDataDir.Size;
    const auto exDirBaseRva = exportDataDir.VirtualAddress;

    if (exDirSize == 0 || exDirBaseRva == 0) {
        std::println("[-] No export directory");
        return 0;
    }

    auto deleter = [](BYTE* ptr) { VirtualFree(ptr, 0, MEM_RELEASE); };
    auto exportDirRaw = std::unique_ptr<BYTE[], decltype(deleter)>(
        static_cast<BYTE*>(VirtualAlloc(nullptr, exDirSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)),
        deleter);

    if (!exportDirRaw) {
        std::println("[-] Failed to allocate export directory buffer");
        return 0;
    }

    if (!driver.ReadMemory(moduleBase + exDirBaseRva, exportDirRaw.get(), exDirSize)) {
        std::println("[-] Failed to read export directory");
        return 0;
    }

    auto* exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(exportDirRaw.get());
    const uintptr_t delta = reinterpret_cast<uintptr_t>(exportDirRaw.get()) - exDirBaseRva;

    auto* nameTable = reinterpret_cast<DWORD*>(exportDir->AddressOfNames + delta);
    auto* ordinalTable = reinterpret_cast<WORD*>(exportDir->AddressOfNameOrdinals + delta);
    auto* functionTable = reinterpret_cast<DWORD*>(exportDir->AddressOfFunctions + delta);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<char*>(nameTable[i] + delta);

        if (funcName != name) {
            continue;
        }

        const WORD ordinal = ordinalTable[i];
        const DWORD functionRva = functionTable[ordinal];

        if (functionRva == 0) {
            std::println("[-] Export '{}' has null RVA", funcName);
            return 0;
        }

        const uintptr_t functionAddr = moduleBase + functionRva;
        std::println("[+] Export '{}' found at 0x{:X}", funcName, functionAddr);

        foundExports.emplace(funcName, functionAddr);
        return functionAddr;
    }

    return 0;
}

bool K32Module::InitModuleInfo() const
{
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (!K32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        std::println("[-] Failed to enumerate device drivers");
        return false;
    }

    const DWORD cDrivers = cbNeeded / sizeof(drivers[0]);

    for (DWORD i = 0; i < cDrivers; ++i) {
        char baseName[256];
        if (!K32GetDeviceDriverBaseNameA(drivers[i], baseName, sizeof(baseName))) {
            continue;
        }

        if (_stricmp(baseName, moduleName.data()) != 0) {
            continue;
        }

        moduleBase = reinterpret_cast<uintptr_t>(drivers[i]);

        IMAGE_DOS_HEADER dosHeader { };
        if (!driver.ReadMemory(moduleBase, &dosHeader, sizeof(dosHeader))) {
            return false;
        }

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        IMAGE_NT_HEADERS64 ntHeaders { };
        if (!driver.ReadMemory(moduleBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) {
            return false;
        }

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        moduleSize = ntHeaders.OptionalHeader.SizeOfImage;
        return true;
    }

    return false;
}
