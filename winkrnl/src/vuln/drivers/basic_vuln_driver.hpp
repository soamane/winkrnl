#pragma once

#ifndef BASIC_VULN_DRIVER_HPP
#define BASIC_VULN_DRIVER_HPP

#include <Windows.h>
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
    virtual bool KeMemMove(uintptr_t dist, uintptr_t src, std::size_t size) = 0;

protected:
    HANDLE hDevice;

private:
    bool init;
    const std::string symbLink;
};

#endif // !BASIC_VULN_DRIVER_HPP
