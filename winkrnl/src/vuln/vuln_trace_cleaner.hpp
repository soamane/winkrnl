#pragma once

#ifndef VULN_TRACE_CLEANER_HPP
#define VULN_TRACE_CLEANER_HPP

#include <memory>
#include <string_view>

class K32Context;
class K32ModuleParser;

class VulnTraceCleaner {
public:
    VulnTraceCleaner(std::shared_ptr<K32Context> k32ctx, std::string_view k32ModuleName = "ntoskrnl.exe");

public:
    bool Cleanup() const;

private:
    bool CleanupPiDDBCacheList() const;

private:
    std::shared_ptr<K32Context> k32ctx;
    std::unique_ptr<K32ModuleParser> moduleParser;
};

#endif // !VULN_TRACE_CLEANER_HPP
