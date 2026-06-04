#pragma once

#ifndef K32_PATTERN_SCANNER_HPP
#define K32_PATTERN_SCANNER_HPP

#include <memory>
#include <cstdint>

class BasicVulnDriver;

class K32PatternScanner {
public:
    explicit K32PatternScanner(std::shared_ptr<BasicVulnDriver> driver);

public:
    uintptr_t FindPatternAddr(uintptr_t moduleBase, size_t moduleSize, const char* pattern, const char* mask) const;

private:
    std::shared_ptr<BasicVulnDriver> driver;
};

#endif // !PATTERN_SCANNER_HPP
