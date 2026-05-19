#pragma once

#ifndef IQVW64_DRIVER_HPP
#define IQVW64_DRIVER_HPP

#include <vuln/drivers/basic_vuln_driver.hpp>

class Iqvw64Driver : public BasicVulnDriver {
public:
    const std::vector<uint8_t>& GetData() const override;
};

#endif // !IQVW64_DRIVER_HPP
