#pragma once

#ifndef VULN_DRIVER_LOADER_HPP
#define VULN_DRIVER_LOADER_HPP

#include <filesystem>
#include <memory>
#include <ntdll.hpp>

class BasicVulnDriver;
class ServiceRegistry;

class VulnDriverLoader {
private:
    VulnDriverLoader();
    ~VulnDriverLoader();

public:
    VulnDriverLoader(VulnDriverLoader&&) = delete;
    VulnDriverLoader(const VulnDriverLoader&) = delete;

    VulnDriverLoader& operator=(VulnDriverLoader&&) = delete;
    VulnDriverLoader& operator=(const VulnDriverLoader&) = delete;

public:
    static VulnDriverLoader& GetInstance();

public:
    bool LoadDriver(std::shared_ptr<BasicVulnDriver> driver);

private:
    bool Load();

public:
    bool Unload();

public:
    static bool EnableLoadPrivileges();

private:
    bool isLoaded;

    std::filesystem::path driverPath;
    std::wstring ntPath;

    std::shared_ptr<BasicVulnDriver> driver;
    std::unique_ptr<ServiceRegistry> registry;
};

#endif // !VULN_DRIVER_LOADER_HPP
