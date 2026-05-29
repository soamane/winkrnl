#include "basic_vuln_driver.hpp"

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

HANDLE BasicVulnDriver::GetDevice()
{
    return hDevice;
}

bool BasicVulnDriver::ReadMemory(uintptr_t address, void* buffer, std::size_t size)
{
    return KeMemMove(reinterpret_cast<uintptr_t>(buffer), address, size);
}

bool BasicVulnDriver::WriteMemory(uintptr_t address, void* buffer, std::size_t size)
{
    return KeMemMove(address, reinterpret_cast<uintptr_t>(buffer), size);
}
