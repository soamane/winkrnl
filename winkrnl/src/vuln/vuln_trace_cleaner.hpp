#pragma once

#ifndef VULN_TRACE_CLEANER_HPP
#define VULN_TRACE_CLEANER_HPP

#include <memory>
#include <functional>
#include <string_view>

class K32Context;
class K32ModuleParser;

class VulnTraceCleaner {
public:
    VulnTraceCleaner(std::shared_ptr<K32Context> k32ctx);

public:
    bool Cleanup() const;

private:
    bool CleanupPiDDBCacheList(const K32ModuleParser& moduleParser) const;
    bool CleanupPiDDBCacheTable(const K32ModuleParser& moduleParser) const;

private:
    bool CleanAvlNode(uintptr_t baseAddr, uintptr_t nodeAddr) const;

private:
    std::shared_ptr<K32Context> k32ctx;
};

#endif // !VULN_TRACE_CLEANER_HPP
