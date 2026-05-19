#pragma once

#ifndef BASIC_VULN_DRIVER_HPP
#define BASIC_VULN_DRIVER_HPP

#include <vector>

class BasicVulnDriver {
public:
    virtual const std::vector<uint8_t>& GetData() const = 0;
};

#endif // !BASIC_VULN_DRIVER_HPP
