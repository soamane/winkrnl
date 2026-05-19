#pragma once

#ifndef BASIC_VULN_DRIVER_HPP
#define BASIC_VULN_DRIVER_HPP

#include <string>
#include <vector>
#include <Windows.h>

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

private:
    HANDLE hDevice;
    bool init;
    const std::string symbLink;
};

#endif // !BASIC_VULN_DRIVER_HPP
