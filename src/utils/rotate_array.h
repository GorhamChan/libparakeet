#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace parakeet_crypto::utils
{

inline void RotateLeft(uint8_t *ptr, size_t len, size_t rotate_pos)
{
    rotate_pos %= len;

    // Backup first X bytes
    std::vector<uint8_t> temp(ptr, ptr + rotate_pos);

    // Copy from offset X to beginning
    std::memmove(ptr, &ptr[rotate_pos], len - rotate_pos);

    // Copy backup data to the end.
    std::memmove(&ptr[len - rotate_pos], temp.data(), rotate_pos);
}

inline void RotateRight(uint8_t *ptr, size_t len, size_t rotate_pos)
{
    rotate_pos %= len;

    RotateLeft(ptr, len, len - rotate_pos);
}

} // namespace parakeet_crypto::utils
