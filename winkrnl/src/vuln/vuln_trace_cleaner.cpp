#include "vuln_trace_cleaner.hpp"

#include <kernel/k32_context.hpp>
#include <kernel/k32_parser.hpp>

#include <utils/cmn_utils.hpp>

#include <ntdll.hpp>
#include <print>

VulnTraceCleaner::VulnTraceCleaner(std::shared_ptr<K32Context> k32ctx)
    : k32ctx(std::move(k32ctx))
{
}

bool VulnTraceCleaner::Cleanup() const
{
    const auto ntkrnlParser = K32ModuleParser(k32ctx, "ntoskrnl.exe");
    if (!CleanupPiDDBCacheList(ntkrnlParser)) {
        std::println("[-] Failed to cleanup vulnerable driver from PiDDBCacheList");
        return false;
    }

    if (!CleanupPiDDBCacheTable(ntkrnlParser)) {
        std::println("[-] Failed to cleanup vulnerable driver from PiDDBCacheTable");
        return false;
    }

    return true;
}

bool VulnTraceCleaner::CleanupPiDDBCacheList(const K32ModuleParser& moduleParser) const
{
    static const auto _PiDDBCacheList = moduleParser.FindAbsoluteAddr("\x48\x8D\x15\x00\x00\x00\x00\x48\x8B\x0D\x00\x00\x00\x00\x00\x00\x00\x74", "xxx????xxx???????x", 3, 7);
    if (!_PiDDBCacheList) {
        std::println("[-] _PiDDBCacheList not found");
        return false;
    }

    uintptr_t link = 0;
    if (!k32ctx->GetDriver().ReadMemory(_PiDDBCacheList, &link, sizeof(link))) {
        std::println("[-] Failed read head of PiDDBCacheList");
        return false;
    }

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

bool VulnTraceCleaner::CleanupPiDDBCacheTable(const K32ModuleParser& moduleParser) const
{
    static const auto _PiDDBCacheTable = moduleParser.FindAbsoluteAddr("\x48\x8D\x0D\x00\x00\x00\x00\x45\x33\xF6\x48\x89\x44\x24", "xxx????xxxxxxx", 3, 7);
    if (!_PiDDBCacheTable) {
        std::println("[-] _PiDDBCacheTable not found");
        return false;
    }

    RTL_BALANCED_LINKS balancedRoot = { 0 };
    if (!k32ctx->GetDriver().ReadMemory(_PiDDBCacheTable, &balancedRoot, sizeof(balancedRoot))) {
        std::println("[-] Failed to read BalancedRoot");
        return false;
    }

    return CleanAvlNode(_PiDDBCacheTable, (uintptr_t)balancedRoot.RightChild);
}

bool VulnTraceCleaner::CleanAvlNode(uintptr_t baseAddr, uintptr_t nodeAddr) const
{
    if (nodeAddr == 0 || nodeAddr == baseAddr) {
        return false;
    }

    RTL_BALANCED_LINKS node = { 0 };
    if (!k32ctx->GetDriver().ReadMemory(nodeAddr, &node, sizeof(node))) {
        return false;
    }

    uintptr_t entryAddr = nodeAddr + sizeof(RTL_BALANCED_LINKS);

    PiDDBCacheEntry entry = { 0 };
    if (!k32ctx->GetDriver().ReadMemory(entryAddr, &entry, sizeof(entry))) {
        return false;
    }

    if (entry.TimeDateStamp == k32ctx->GetDriver().GetTimeStamp()) {
        ULONG timestamp = Utils::Common::GenerateRandomTimeStamp();
        k32ctx->GetDriver().WriteMemory(
            entryAddr + offsetof(PiDDBCacheEntry, TimeDateStamp),
            &timestamp, sizeof(timestamp));

        USHORT zeroLen = 0;
        k32ctx->GetDriver().WriteMemory(
            entryAddr + offsetof(PiDDBCacheEntry, DriverName),
            &zeroLen, sizeof(zeroLen));

        std::println("[+] Vulnerable driver cleaned in PiDDBCacheTable at 0x{:X}", entryAddr);
        return true;
    }

    if (CleanAvlNode(baseAddr, (uintptr_t)node.LeftChild)) {
        return true;
    }

    return CleanAvlNode(baseAddr, (uintptr_t)node.RightChild);
}