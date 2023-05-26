#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace parakeet_crypto::migu3d
{

constexpr std::size_t kMiguFinalKeySize = 32;
constexpr std::size_t kMiguFreqAnalysisSize = 0x1000; // 4k

static_assert((kMiguFreqAnalysisSize % kMiguFinalKeySize) == 0,
              "kMiguFreqAnalysisSize should be multiple of kMiguFinalKeySize");

inline bool isUpperHexChar(uint8_t chr)
{
    return (chr >= '0' && chr <= '9') || (chr >= 'A' && chr <= 'F');
}

inline std::optional<std::array<uint8_t, kMiguFinalKeySize>> SearchByFreqAnalysis(const uint8_t *header, size_t len)
{
    std::array<uint8_t, kMiguFinalKeySize> result{};
    std::array<std::map<uint8_t, size_t>, kMiguFinalKeySize> freq;

    const auto *p_header = header;
    for (size_t i = 0; len > 0; p_header++, len--)
    {
        auto byte = *p_header;

        if (isUpperHexChar(byte))
        {
            auto &charFreq = freq[i];
            if (charFreq.find(byte) == charFreq.end())
            {
                charFreq[byte] = 1;
            }
            else
            {
                charFreq[byte] += 1;
            }
        }

        i = (i + 1) % kMiguFinalKeySize;
    }

    int idx = 0;
    for (auto &charFreq : freq)
    {
        if (charFreq.empty())
        {
            return {};
        }

        auto max_item = std::max_element(charFreq.cbegin(), charFreq.cend(), [](const auto &left, const auto &right) {
            return left.second < right.second;
        });
        result[idx] = max_item->first;
        idx++;
    }

    return result;
}

} // namespace parakeet_crypto::migu3d
