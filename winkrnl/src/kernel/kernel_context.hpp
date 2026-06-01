#pragma once

#ifndef K32_CONTEXT_HPP
#define K32_CONTEXT_HPP

#include <ntdll.hpp>
#include <print>
#include <string_view>
#include <vuln/drivers/basic_vuln_driver.hpp>

class K32Context {
public:
    explicit K32Context(BasicVulnDriver* driver);

public:
    BasicVulnDriver* GetDriver();

public:
    uintptr_t AllocatePool(POOL_TYPE poolType, std::size_t size);
    bool FreePool(uintptr_t address);

private:
    template <typename T, typename... A>
    bool InvokeK32Routine(T* outResult, uintptr_t functionAddress, const A... args);

    template <typename... A>
    inline bool InvokeK32Routine(uintptr_t functionAddress, const A... args);

private:
    uintptr_t GetK32ModuleAddr(std::string_view moduleName);
    uintptr_t GetK32ExportProcAddr(std::string_view moduleName, std::string_view functionName);

private:
    BasicVulnDriver* driver;
};

#endif // !K32_CONTEXT_HPP

template <typename T, typename... A>
inline bool K32Context::InvokeK32Routine(T* outResult, uintptr_t functionAddress, const A... args)
{
    static uint8_t jmp[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
    *reinterpret_cast<uintptr_t*>(&jmp[2]) = functionAddress;

    static const auto exNtCloseAddr = GetK32ExportProcAddr("ntoskrnl.exe", "NtAddAtom");
    if (!exNtCloseAddr) {
        std::println("[-] Failed to get address of export function");
        return false;
    }

    uint8_t origin[ARRAYSIZE(jmp)];
    if (!driver->ReadMemory(exNtCloseAddr, origin, sizeof(jmp))) {
        std::println("[-] Failed to read origin function instruction");
        return false;
    }

    if (!driver->WriteMappedMemory(exNtCloseAddr, jmp, sizeof(jmp))) {
        std::println("[-] Failed to write jmp hook");
        return false;
    }

    using FN = T(__stdcall*)(A...);

    if constexpr (std::same_as<T, void>) {
        reinterpret_cast<FN>(&NtAddAtom)(args...);
    } else {
        *outResult = reinterpret_cast<FN>(&NtAddAtom)(args...);
    }

    return driver->WriteMappedMemory(exNtCloseAddr, origin, sizeof(jmp));
}

template <typename... A>
inline bool K32Context::InvokeK32Routine(uintptr_t functionAddress, const A... args)
{
    return InvokeK32Routine<void>(static_cast<void*>(nullptr), functionAddress, args...);
}
