#include "fs_utils.hpp"

#include "cmn_utils.hpp"
#include <fstream>

std::filesystem::path Utils::FS::GenerateRandomTempPath(std::string_view extension)
{
    auto filename = Utils::Common::GenerateRandomString(16);
    filename += extension;

    const auto tempDir = std::filesystem::temp_directory_path();
    return tempDir / filename;
}

std::vector<uint8_t> Utils::FS::ReadBytesFromFile(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return { };
    }

    const auto size = std::filesystem::file_size(path);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));

    return buffer;
}

bool Utils::FS::CreateFileFromMemory(const std::filesystem::path& path, const std::vector<uint8_t>& data)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size()));

    return file.good();
}
