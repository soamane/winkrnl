#pragma once

#ifndef PE_UTILS_HPP
#define PE_UTILS_HPP

#include <string>
#include <vector>
#include <windows.h>

namespace Utils::PE {
struct Import {
    struct Thunk {
        std::string name;
        uintptr_t* address;
    };

    std::string name;
    std::vector<Thunk> thunks;
};

struct Relocation {
    uintptr_t address;
    WORD* infoPtr;
    WORD countOfEntries;
};

PIMAGE_NT_HEADERS GetNtHeaders(void* image);
std::vector<Import> GetImports(void* image, PIMAGE_NT_HEADERS ntHeaders);
std::vector<Relocation> GetRelocations(void* image, PIMAGE_NT_HEADERS ntHeaders);
}

#endif // !PE_UTILS_HPP
