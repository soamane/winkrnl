#pragma once

#ifndef K32_MODULE_PARSER_HPP
#define K32_MODULE_PARSER_HPP

#include <memory>
#include <string>

class K32Module;
class BasicVulnDriver;

class K32ModuleParser {
public:
    K32ModuleParser(const BasicVulnDriver& driver, K32Module* parent);

public:
    uintptr_t FindAbsoluteAddr(
        const char* pattern,
        const char* mask,
        std::size_t opcodeOffset, std::size_t instrSize) const;

    uintptr_t FindPatternAddr(const char* pattern, const char* mask) const;

private:
    uintptr_t ResolveAbsoluteAddr(uintptr_t instrAddr, std::size_t instrOffset, std::size_t instrSize) const;

private:
    const BasicVulnDriver& driver;
    K32Module* parent;
};

#endif // !K32_MODULE_PARSER_HPP
