#pragma once

#ifndef K32_MODULE_PARSER_HPP
#define K32_MODULE_PARSER_HPP

#include <memory>
#include <string>

class K32Context;
class BasicVulnDriver;

class K32ModuleParser {
public:
    K32ModuleParser(std::shared_ptr<K32Context> k32ctx, std::string_view moduleName);

public:
    uintptr_t FindAbsoluteAddr(
        const char* pattern,
        const char* mask,
        std::size_t opcodeOffset, std::size_t instrSize) const;

    uintptr_t FindPatternAddr(const char* pattern, const char* mask) const;

private:
    uintptr_t ResolveAbsoluteAddr(uintptr_t instrAddr, std::size_t instrOffset, std::size_t instrSize) const;

private:
    const uintptr_t moduleBase;
    const std::size_t moduleSize;
    const BasicVulnDriver& driver;
};

#endif // !K32_MODULE_PARSER_HPP
