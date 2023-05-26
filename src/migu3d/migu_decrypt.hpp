#pragma once

#include "freq_analysis.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace parakeet_crypto::migu3d
{

inline void DecryptSegment(uint8_t *buffer, size_t len, size_t offset, const uint8_t *key)
{
    for (; len > 0; buffer++, len--)
    {
        offset %= kMiguFinalKeySize;

        *buffer -= key[offset];

        offset++;
    }
}

} // namespace parakeet_crypto::migu3d
