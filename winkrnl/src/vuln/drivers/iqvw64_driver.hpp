#pragma once

#ifndef IQVW64_DRIVER_HPP
#define IQVW64_DRIVER_HPP

#include <vuln/drivers/basic_vuln_driver.hpp>

class Iqvw64Driver : public BasicVulnDriver {
public:
    Iqvw64Driver(std::string_view symbLink);

public:
    uintptr_t GetTimeStamp() const override;
    const std::vector<uint8_t>& GetData() const override;

private:
    bool KeMemMove(uintptr_t dist, uintptr_t src, std::size_t size) const override;
    bool KeUnmapIoSpace(uintptr_t virtualAddr, std::size_t size) const override;
    uintptr_t KeMapIoSpace(uintptr_t physicalAddr, std::size_t size) const override;
    uintptr_t KeGetPhysicalAddress(uintptr_t virtualAddr) const override;
};

#endif // !IQVW64_DRIVER_HPP
