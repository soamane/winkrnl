#include "fs_utils.hpp"

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
