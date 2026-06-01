#pragma once

#ifndef BASIC_VULN_DRIVER_HPP
#define BASIC_VULN_DRIVER_HPP

#include <Windows.h>
#include <print>
#include <string>
#include <vector>

class BasicVulnDriver {
public:
    BasicVulnDriver(std::string_view symbLink);
    virtual ~BasicVulnDriver();

public:
    bool OpenDevice();
    void CloseDevice();

    HANDLE GetDevice();

public:
    virtual const std::vector<uint8_t>& GetData() const = 0;

public:
    virtual bool ReadMemory(uintptr_t address, void* buffer, std::size_t size);
    virtual bool WriteMemory(uintptr_t address, void* buffer, std::size_t size);
    virtual bool WriteMappedMemory(uintptr_t address, void* buffer, std::size_t size);

public:
    virtual bool KeMemMove(uintptr_t dist, uintptr_t src, std::size_t size) = 0;
    virtual bool KeUnmapIoSpace(uintptr_t virtualAddr, std::size_t size) = 0;
    virtual uintptr_t KeMapIoSpace(uintptr_t physicalAddr, std::size_t size) = 0;
    virtual uintptr_t KeGetPhysicalAddress(uintptr_t virtualAddr) = 0;

protected:
    template <typename T>
    bool SendIoRequest(DWORD controlCode, const T& req);

private:
    HANDLE hDevice;
    bool init;
    const std::string symbLink;
};

#endif // !BASIC_VULN_DRIVER_HPP

template <typename T>
inline bool BasicVulnDriver::SendIoRequest(DWORD controlCode, const T& req)
{
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDevice, controlCode, const_cast<void*>(static_cast<const void*>(&req)), sizeof(req), nullptr, 0, &bytesReturned, nullptr)) {
        std::println("[-] DeviceIoControl failed: 0x{:X}, bytes returned: {}", GetLastError(), bytesReturned);
        return false;
    }
    return true;
}
