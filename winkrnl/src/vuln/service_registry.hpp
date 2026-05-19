#pragma once

#ifndef SERVICE_REGISTRY_HPP
#define SERVICE_REGISTRY_HPP

#include <filesystem>

class ServiceRegistry {
public:
    ServiceRegistry(const std::filesystem::path& drvPath);

public:
    bool CreateRegistryEntry() const;
    bool DeleteRegistryEntry() const;

private:
    const std::filesystem::path drvPath;

    const std::string svcName;
    const std::string subKey;
};

#endif // !SERVICE_REGISTRY_HPP
