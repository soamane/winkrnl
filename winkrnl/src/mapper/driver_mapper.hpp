#pragma once

#ifndef DRIVER_MAPPER_HPP
#define DRIVER_MAPPER_HPP

#include <utils/pe_utils.hpp>

#include <memory>
#include <windows.h>

class K32Context;
class K32Module;

class DriverMapper {
public:
    DriverMapper(std::shared_ptr<K32Context> k32ctx, std::shared_ptr<K32Module> k32Module);

public:
    bool Map(void* fileBytes);

private:
    void CopyToMemory(uintptr_t baseAddress, PIMAGE_NT_HEADERS ntHeaders, void* data);
    bool ResolveImports(const std::vector<Utils::PE::Import>& imports);
    void ResolveRelocations(uintptr_t baseAddress, PIMAGE_NT_HEADERS ntHeaders, const std::vector<Utils::PE::Relocation>& relocs);

private:
    std::shared_ptr<K32Context> k32ctx;
    std::shared_ptr<K32Module> k32Module;
};

#endif // !DRIVER_MAPPER_HPP
