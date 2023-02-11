#include <algorithm>
#include <parakeet-crypto/xmly/scramble_key.h>
#include <utils/logger.h>

#include <cassert>

namespace parakeet_crypto::xmly
{

constexpr double kMinMulInit{0.00};
constexpr double kMaxMulInit{1.00};
constexpr double kMinMulStep{3.57};
constexpr double kMaxMulStep{4.00};

std::optional<std::vector<uint16_t>> CreateScrambleKey(double mul_init, double mul_step, std::size_t len)
{
    if (mul_init < kMinMulInit || mul_init > kMaxMulInit)
    {
        logger::WARN() << "mul_init is out of range. "
                       << "expected [" << kMinMulInit << ", " << kMaxMulInit << "], "
                       << "got '" << mul_init << "'";
        return {};
    }
    if (mul_step < kMinMulStep || mul_step > kMaxMulStep)
    {
        logger::WARN() << "mul_step is out of range. "
                       << "expected [" << kMinMulStep << ", " << kMaxMulStep << "], "
                       << "got '" << mul_step << "'";
        return {};
    }

    std::vector<double> vec_data(len, 0);

    double value = mul_init;
    std::for_each(vec_data.begin(), vec_data.end(), [&value, mul_step](auto &item) {
        item = value;
        value = value * mul_step * (1 - value);
    });

    // Sort it!
    std::vector<double> vec_sorted(vec_data);
    std::sort(vec_sorted.begin(), vec_sorted.end());

    // Look up its index from sorted version.
    std::vector<uint16_t> indexes(len, 0);
    for (auto i = 0; i < len; i++)
    {
        auto it_found = std::find(vec_sorted.begin(), vec_sorted.end(), vec_data[i]);
        auto scrambled_index = std::distance(vec_sorted.begin(), it_found);
        indexes[i] = scrambled_index;

        // When the value duplicates, use the next index.
        // This value cannot be negative.
        vec_sorted[scrambled_index] = -1;
    }

    return indexes;
}

std::optional<std::array<uint16_t, kXimalayaScrambleKeyLen>> CreateScrambleKey(double mul_init, double mul_step)
{
    if (auto table = CreateScrambleKey(mul_init, mul_step, kXimalayaScrambleKeyLen))
    {
        std::array<uint16_t, kXimalayaScrambleKeyLen> result{};
        std::copy(table->begin(), table->end(), result.begin());
        return result;
    }

    return {};
}

} // namespace parakeet_crypto::xmly
