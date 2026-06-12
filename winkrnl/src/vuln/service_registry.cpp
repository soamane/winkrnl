#include "service_registry.hpp"

#include <spdlog/spdlog.h>
#include <utils/cmn_utils.hpp>

#include <Windows.h>

ServiceRegistry::ServiceRegistry(const std::filesystem::path& drvPath)
    : drvPath(drvPath)
    , svcName(drvPath.stem().string())
    , subKey("SYSTEM\\CurrentControlSet\\Services\\" + svcName)
{
}

bool ServiceRegistry::CreateRegistryEntry() const
{
    HKEY hKey;
    LSTATUS status = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE, subKey.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (status != ERROR_SUCCESS) {
        spdlog::error("Failed to create registry key '{}' (0x{:X})", subKey, status);
        return false;
    }

    const std::string ntLink = "\\??\\" + drvPath.string();
    status = RegSetValueExA(hKey, "ImagePath", 0, REG_EXPAND_SZ,
        reinterpret_cast<const BYTE*>(ntLink.c_str()),
        static_cast<DWORD>(ntLink.size() + 1));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        spdlog::error("Failed to set ImagePath '{}' (0x{:X})", ntLink, status);
        return false;
    }

    DWORD svcType = SERVICE_KERNEL_DRIVER;
    status = RegSetValueExA(hKey, "Type", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&svcType), sizeof(svcType));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        spdlog::error("Failed to set Type (0x{:X})", status);
        return false;
    }

    DWORD startType = SERVICE_DEMAND_START;
    status = RegSetValueExA(hKey, "Start", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&startType), sizeof(startType));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        spdlog::error("Failed to set Start (0x{:X})", status);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

bool ServiceRegistry::DeleteRegistryEntry() const
{
    LSTATUS status = RegDeleteKeyExA(
        HKEY_LOCAL_MACHINE,
        subKey.c_str(),
        KEY_WOW64_64KEY,
        0);

    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        spdlog::error("Failed to delete registry key '{}' (0x{:X})", subKey, status);
        return false;
    }

    return true;
}