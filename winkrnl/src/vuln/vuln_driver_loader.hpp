#pragma once

#ifndef VULN_DRIVER_LOADER_HPP
#define VULN_DRIVER_LOADER_HPP

#include <filesystem>
#include <memory>
#include <ntdll.hpp>

class BasicVulnDriver;
class ServiceRegistry;

class VulnDriverLoader {
public:
    VulnDriverLoader(std::unique_ptr<BasicVulnDriver> driver);
    ~VulnDriverLoader();

public:
    bool Load();
    bool Unload();

private:
    std::wstring BuildNtPath() const;

private:
    std::filesystem::path drvPath;

    std::unique_ptr<BasicVulnDriver> driver;
    std::unique_ptr<ServiceRegistry> registry;
};

bool EnableLoadPrivilege();

#endif // !VULN_DRIVER_LOADER_HPP
