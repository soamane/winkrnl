#pragma once

#ifndef IQVW64_DRIVER_HPP
#define IQVW64_DRIVER_HPP

#include <vuln/drivers/basic_vuln_driver.hpp>

class Iqvw64Driver : public BasicVulnDriver {
public:
    Iqvw64Driver(std::string_view symbLink);

public:
    const std::vector<uint8_t>& GetData() const override;

public:
    bool KeMemMove(uintptr_t dist, uintptr_t src, std::size_t size) override;
};

#endif // !IQVW64_DRIVER_HPP
