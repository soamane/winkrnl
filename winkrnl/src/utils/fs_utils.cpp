#include "fs_utils.hpp"

#include "cmn_utils.hpp"
#include <fstream>

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
