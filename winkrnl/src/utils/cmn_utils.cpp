#include "cmn_utils.hpp"

#include <random>

uintptr_t Utils::Common::GenerateRandomTimeStamp()
{
    static constexpr uintptr_t kMinTimestamp = 0x5A4AFB80UL; // 2018-01-01
    static constexpr uintptr_t kMaxTimestamp = 0x6771D880UL; // 2024-12-31

    static std::mt19937 rng { std::random_device { }() };
    static std::uniform_int_distribution<uintptr_t> dist(kMinTimestamp, kMaxTimestamp);

    return dist(rng);
}

std::string Utils::Common::GenerateRandomString(std::size_t length)
{
    constexpr std::string_view charset = "abcdefghijklmnopqrstuvwxyz"
                                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                         "0123456789";

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dist(gen)];
    }

    return result;
}
