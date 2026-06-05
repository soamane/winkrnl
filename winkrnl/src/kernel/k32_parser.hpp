#pragma once

#ifndef K32_MODULE_PARSER_HPP
#define K32_MODULE_PARSER_HPP

#include <cstdint>
#include <memory>

class BasicVulnDriver;

class K32ModuleParser {
public:
    explicit K32ModuleParser(std::shared_ptr<BasicVulnDriver> driver);

public:
    uintptr_t ResolveAbsoluteAddr(uintptr_t instrAddr, std::size_t instrOffset, std::size_t instrSize) const;
    uintptr_t FindPatternAddr(uintptr_t moduleBase, size_t moduleSize, const char* pattern, const char* mask) const;

private:
    std::shared_ptr<BasicVulnDriver> driver;
};

#endif // !K32_MODULE_PARSER_HPP
