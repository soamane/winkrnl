#include <filesystem>
#include <print>

#include "utils/fs_utils.hpp"

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::println("Usage: winkrnl.exe <driver_path>");
        return 0;
    }

    std::filesystem::path driverPath = argv[1];
    if (!std::filesystem::exists(driverPath)) {
        std::println("[-] File '{}' doesn't exist", driverPath.stem().string());
        return 1;
    }

    /*
        You can remove this check if you want to accept any file type
        (e.g. to bypass extension-based detection)
    */
    if (driverPath.extension() != ".sys") {
        std::println("[-] File must have a .sys extension");
        return 1;
    }

    const auto driverBytes = Utils::FS::ReadBytesFromFile(driverPath);
    if (driverBytes.empty()) {
        std::println("[-] Failed to read bytes from driver's file");
        return 1;
    }


    return 0;
}