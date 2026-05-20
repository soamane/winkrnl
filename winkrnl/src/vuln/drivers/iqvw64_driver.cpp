#include "iqvw64_driver.hpp"

#include <vulnerables/iqvw64_data.hpp>

Iqvw64Driver::Iqvw64Driver(std::string_view symbLink)
    : BasicVulnDriver(std::move(symbLink))
{
}

const std::vector<uint8_t>& Iqvw64Driver::GetData() const
{
    return iqvw64_data;
}
