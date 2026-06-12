#pragma once

#ifndef FILE_SYSTEM_UTILS_HPP
#define FILE_SYSTEM_UTILS_HPP

#include <filesystem>
#include <vector>

namespace Utils::FS {
[[nodiscard]] std::vector<uint8_t> ReadBytesFromFile(const std::filesystem::path& path);
bool CreateFileFromMemory(const std::filesystem::path& path, const std::vector<uint8_t>& data);
}

#endif // !FILE_SYSTEM_UTILS_HPP
