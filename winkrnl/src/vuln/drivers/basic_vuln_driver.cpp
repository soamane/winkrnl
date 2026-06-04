#include "basic_vuln_driver.hpp"

#include <print>

BasicVulnDriver::BasicVulnDriver(std::string_view symbLink)
    : hDevice(INVALID_HANDLE_VALUE)
    , init(false)
    , symbLink(symbLink)
{
}

BasicVulnDriver::~BasicVulnDriver()
{
    CloseDevice();
}

bool BasicVulnDriver::OpenDevice()
{
    if (hDevice != INVALID_HANDLE_VALUE) {
        return true;
    }

    hDevice = CreateFileA(symbLink.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return hDevice != INVALID_HANDLE_VALUE;
}

void BasicVulnDriver::CloseDevice()
{
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
    hDevice = INVALID_HANDLE_VALUE;
}

HANDLE BasicVulnDriver::GetDevice() const
{
    return hDevice;
}

bool BasicVulnDriver::ReadMemory(uintptr_t address, void* buffer, std::size_t size) const
{
    return KeMemMove(reinterpret_cast<uintptr_t>(buffer), address, size);
}

bool BasicVulnDriver::WriteMemory(uintptr_t address, void* buffer, std::size_t size) const
{
    return KeMemMove(address, reinterpret_cast<uintptr_t>(buffer), size);
}

bool BasicVulnDriver::WriteMappedMemory(uintptr_t address, void* buffer, std::size_t size) const
{
    uintptr_t physicalAddr = KeGetPhysicalAddress(address);
    if (!physicalAddr) {
        return false;
    }

    uintptr_t virtualAddr = KeMapIoSpace(physicalAddr, size);
    if (!virtualAddr) {
        return false;
    }

    if (!WriteMemory(virtualAddr, buffer, size)) {
        KeUnmapIoSpace(virtualAddr, size);
        return false;
    }

    return KeUnmapIoSpace(virtualAddr, size);
}
