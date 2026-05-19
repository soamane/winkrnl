#pragma once

#ifndef VULN_DRIVER_LOADER_HPP
#define VULN_DRIVER_LOADER_HPP

#include <filesystem>
#include <memory>

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
    std::filesystem::path tempPath;
    std::unique_ptr<BasicVulnDriver> driver;
    std::unique_ptr<ServiceRegistry> registry;
};

bool EnableLoadPrivilege();

#endif // !VULN_DRIVER_LOADER_HPP
