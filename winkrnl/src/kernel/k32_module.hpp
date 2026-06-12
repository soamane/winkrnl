#pragma once

#ifndef K32_MODULE_HPP
#define K32_MODULE_HPP

#include <memory>
#include <string>
#include <map>

class BasicVulnDriver;

class K32Module {
public:
    K32Module(const BasicVulnDriver& driver, std::string_view moduleName);

public:
    std::size_t GetK32ModuleSize() const;
    std::string GetK32ModuleName() const;
    std::uintptr_t GetK32ModuleBaseAddress() const;

public:
    uintptr_t GetK32ExportProcAddress(std::string_view funcName) const;

private:
    bool InitModuleInfo() const;

private:
    const BasicVulnDriver& driver;

    std::string moduleName;
    mutable std::size_t moduleSize;
    mutable std::uintptr_t moduleBase;
    mutable std::map<std::string, uintptr_t> foundExports;
};

#endif // !K32_MODULE_HPP
