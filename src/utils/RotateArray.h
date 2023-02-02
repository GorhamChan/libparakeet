#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils
{

template <size_t SIZE, size_t ROTATE_POS> void RotateLeft(uint8_t *ptr)
{
    constexpr size_t rotate_pos = ROTATE_POS % SIZE;

    std::array<uint8_t, SIZE> temp{};
    std::copy_n(ptr + rotate_pos, SIZE - rotate_pos, &temp.at(0));
    std::copy_n(ptr, rotate_pos, &temp.at(SIZE - rotate_pos));
    std::copy(temp.begin(), temp.end(), ptr);
}

template <size_t SIZE, size_t ROTATE_POS> void RotateRight(uint8_t *ptr)
{
    constexpr size_t rotate_pos = ROTATE_POS % SIZE;

    RotateLeft<SIZE, SIZE - ROTATE_POS>(ptr);
}

} // namespace parakeet_crypto::utils
