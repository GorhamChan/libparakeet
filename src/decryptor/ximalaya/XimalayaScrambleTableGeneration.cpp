#include "XimalayaScrambleTableGeneration.h"

#include <algorithm>
#include <span>
#include <vector>

#include <cassert>

namespace parakeet_crypto::decryptor::ximalaya
{

void GenerateScrambleTable(std::span<uint16_t> result, double mul_init, double mul_step)
{
    assert(("mul_init is out of range.", mul_init >= 0.00 && mul_init <= 1.00));
    assert(("mul_step is out of range.", mul_step >= 3.57 && mul_step <= 4.00));

    const auto n = result.size();
    std::vector<double> vec_data(n);

    double next_value = mul_init;
    for (auto i = 0; i < n; i++)
    {
        vec_data[i] = next_value;
        next_value = next_value * mul_step * (1 - next_value);
    }

    // Sort it!
    std::vector<double> vec_sorted(vec_data);
    std::ranges::sort(vec_sorted.begin(), vec_sorted.end());

    // Look up its index from sorted version.
    for (auto i = 0; i < n; i++)
    {
        auto it_found = std::ranges::find(vec_sorted.cbegin(), vec_sorted.cend(), vec_data[i]);
        auto scrambled_index = std::distance(vec_sorted.cbegin(), it_found);
        result[i] = static_cast<uint16_t>(scrambled_index);

        // When the value duplicates, use the next index.
        // This value cannot be negative.
        vec_sorted[scrambled_index] = -1;
    }
}

} // namespace parakeet_crypto::decryptor::ximalaya
