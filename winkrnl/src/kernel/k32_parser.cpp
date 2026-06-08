#include "k32_parser.hpp"

#include <kernel/k32_context.hpp>
#include <vuln/drivers/basic_vuln_driver.hpp>

#include <vector>

K32ModuleParser::K32ModuleParser(std::shared_ptr<K32Context> k32ctx, std::string_view moduleName)
    : moduleBase(k32ctx->GetK32ModuleAddr(moduleName))
    , moduleSize(k32ctx->GetK32ModuleSize(moduleName))
    , driver(k32ctx->GetDriver())
{
}

uintptr_t K32ModuleParser::FindAbsoluteAddr(const char* pattern, const char* mask, std::size_t opcodeOffset, std::size_t instrSize) const
{
    const auto instrAddr = FindPatternAddr(pattern, mask);
    if (!instrAddr) {
        std::println("[-] Failed to find pattern address");
        return 0;
    }

    return ResolveAbsoluteAddr(instrAddr, opcodeOffset, instrSize);
}

uintptr_t K32ModuleParser::FindPatternAddr(const char* pattern, const char* mask) const
{
    std::vector<std::uint8_t> buffer(moduleSize);
    if (!driver.ReadMemory(moduleBase, buffer.data(), moduleSize)) {
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

uintptr_t K32ModuleParser::ResolveAbsoluteAddr(uintptr_t instrAddr, std::size_t instrOffset, std::size_t instrSize) const
{
    std::int32_t relOffset = 0;
    if (!driver.ReadMemory(instrAddr + instrOffset, &relOffset, sizeof(relOffset))) {
        return 0;
    }

    return instrAddr + instrSize + relOffset;
}