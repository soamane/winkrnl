#include <Windows.h>
#include <filesystem>
#include <print>

#include <utils/fs_utils.hpp>

#include <vuln/drivers/iqvw64_driver.hpp>
#include <vuln/vuln_driver_loader.hpp>

int main(int argc, char** argv)
{
    if (!EnableLoadPrivilege()) {
        std::println("[-] Failed to allow load privileges");
        return 1;
    }

    // if (argc != 2) {
    //     std::println("Usage: {} <driver_path>", argv[0]);
    //     return 1;
    // }

    // std::filesystem::path driverPath = argv[1];
    // if (!std::filesystem::exists(driverPath)) {
    //     std::println("[-] File '{}' doesn't exist", driverPath.stem().string());
    //     return 1;
    // }

    ///*
    //    You can remove this check if you want to accept any file type
    //    (e.g. to bypass extension-based detection)
    //*/
    // if (driverPath.extension() != ".sys") {
    //    std::println("[-] File must have a .sys extension");
    //    return 1;
    //}

    // const auto driverBytes = Utils::FS::ReadBytesFromFile(driverPath);
    // if (driverBytes.empty()) {
    //     std::println("[-] Failed to read bytes from driver");
    //     return 1;
    // }

    VulnDriverLoader vulnDrvLoader = VulnDriverLoader(
        std::make_unique<Iqvw64Driver>("\\\\.\\Nal"));

    if (!vulnDrvLoader.Load()) {
        std::println("[-] Failed to load vulnerable driver");
        return 1;
    }

    std::println("[+] Driver successfully loaded");

    BasicVulnDriver* driver = vulnDrvLoader.GetDriver();

    /*
        TODO: Manual mapping your driver...
    */

    if (!vulnDrvLoader.Unload()) {
        std::println("[-] Failed to unload vulnerable driver");
        return 1;
    }

    std::println("[+] Driver successfully unloaded");
    return 0;
}