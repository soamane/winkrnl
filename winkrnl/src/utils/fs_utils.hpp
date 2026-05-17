#pragma once

#ifndef FILE_SYSTEM_UTILS_HPP
#define FILE_SYSTEM_UTILS_HPP

#include <filesystem>
#include <vector>

namespace Utils::FS {
[[nodiscard]] std::vector<uint8_t> ReadBytesFromFile(const std::filesystem::path& path);
}

#endif // !FILE_SYSTEM_UTILS_HPP
