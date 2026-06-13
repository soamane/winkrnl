#pragma once

#ifndef VULN_TRACE_CLEANER_HPP
#define VULN_TRACE_CLEANER_HPP

#include <functional>
#include <memory>
#include <string_view>

class K32Module;
class K32Context;

class VulnTraceCleaner {
public:
    VulnTraceCleaner(std::shared_ptr<K32Context> k32ctx, std::shared_ptr<K32Module> k32Module);

public:
    bool Cleanup() const;

private:
    bool CleanupPiDDBCacheList() const;
    bool CleanupPiDDBCacheTable() const;
    bool CleanupPsLoadedModuleList() const;
    bool CleanupKernelHashBucketList() const;


private:
    std::shared_ptr<K32Context> k32ctx;
    std::shared_ptr<K32Module> k32Module;
};

#endif // !VULN_TRACE_CLEANER_HPP
