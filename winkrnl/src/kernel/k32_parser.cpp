#include "k32_parser.hpp"

#include <vuln/drivers/basic_vuln_driver.hpp>

#include <vector>

K32ModuleParser::K32ModuleParser(std::shared_ptr<BasicVulnDriver> driver)
    : driver(std::move(driver))
{
}

uintptr_t K32ModuleParser::ResolveAbsoluteAddr(uintptr_t instrAddr, std::size_t instrOffset, std::size_t instrSize) const
{
    std::int32_t relOffset = 0;
    if (!driver->ReadMemory(instrAddr + instrOffset, &relOffset, sizeof(relOffset))) {
        return 0;
    }

    return instrAddr + instrSize + relOffset;
}

uintptr_t K32ModuleParser::FindPatternAddr(uintptr_t moduleBase, size_t moduleSize, const char* pattern, const char* mask) const
{
    std::vector<std::uint8_t> buffer(moduleSize);
    if (!driver->ReadMemory(moduleBase, buffer.data(), moduleSize)) {
        return 0;
    }

    const auto maskLen = strlen(mask);
    if (maskLen == 0 || maskLen > moduleSize) {
        return 0;
    }

    for (size_t i = 0; i <= moduleSize - maskLen; ++i) {
        bool found = true;

        for (size_t j = 0; j < maskLen; ++j) {
            if (mask[j] == 'x' && static_cast<uint8_t>(pattern[j]) != buffer[i + j]) {
                found = false;
                break;
            }
        }

        if (found) {
            return moduleBase + i;
        }
    }

    return 0;
}
