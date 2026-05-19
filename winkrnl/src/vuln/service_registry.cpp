#include "service_registry.hpp"

#include <utils/cmn_utils.hpp>

#include <Windows.h>
#include <print>

ServiceRegistry::ServiceRegistry(const std::filesystem::path& drvPath)
    : drvPath(drvPath)
    , svcName(Utils::Common::GenerateRandomString(16))
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
        std::println("[-] Failed to create registry key (0x{:X})", status);
        return false;
    }

    const std::string ntLink = "\\??\\" + drvPath.string();
    status = RegSetValueExA(hKey, "ImagePath", 0, REG_EXPAND_SZ,
        reinterpret_cast<const BYTE*>(ntLink.c_str()),
        static_cast<DWORD>(ntLink.size() + 1));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::println("[-] Failed to set ImagePath (0x{:X})", status);
        return false;
    }

    DWORD svcType = SERVICE_KERNEL_DRIVER;
    status = RegSetValueExA(hKey, "Type", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&svcType), sizeof(svcType));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::println("[-] Failed to set Type (0x{:X})", status);
        return false;
    }

    DWORD startType = SERVICE_DEMAND_START;
    status = RegSetValueExA(hKey, "Start", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&startType), sizeof(startType));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::println("[-] Failed to set Start (0x{:X})", status);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

bool ServiceRegistry::DeleteRegistryEntry() const
{
    return RegDeleteKeyA(HKEY_LOCAL_MACHINE, subKey.c_str()) == ERROR_SUCCESS;
}