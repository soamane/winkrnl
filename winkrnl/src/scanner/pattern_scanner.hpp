#pragma once

#ifndef PATTERN_SCANNER_HPP
#define PATTERN_SCANNER_HPP

#include <memory>
#include <cstdint>

class BasicVulnDriver;

class PatternScanner {
public:
    explicit PatternScanner(std::shared_ptr<BasicVulnDriver> driver);
    ~PatternScanner();

public:
    uintptr_t FindPatternAddr(uintptr_t moduleBase, size_t moduleSize, const char* pattern, const char* mask) const;

private:
    std::shared_ptr<BasicVulnDriver> driver;
};

#endif // !PATTERN_SCANNER_HPP
