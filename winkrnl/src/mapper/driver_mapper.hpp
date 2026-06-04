#pragma once

#ifndef DRIVER_MAPPER_HPP
#define DRIVER_MAPPER_HPP

#include <utils/pe_utils.hpp>

#include <windows.h>

class K32Context;

class DriverMapper {
public:
    DriverMapper(K32Context* k32ctx);

public:
    bool Map(void* image);

private:
    void CopyToMemory(uintptr_t baseAddress, PIMAGE_NT_HEADERS ntHeaders, void* data);
    bool ResolveImports(const std::vector<Utils::PE::Import>& imports);
    void ResolveRelocations(uintptr_t baseAddress, PIMAGE_NT_HEADERS ntHeaders, const std::vector<Utils::PE::Relocation>& relocs);

private:
    K32Context* k32ctx;
};

#endif // !DRIVER_MAPPER_HPP
