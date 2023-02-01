#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::qmc::tea_key
{

constexpr size_t kSize = 16;

class SimpleKey
{
  public:
    SimpleKey() = default;

    inline uint8_t Next()
    {
        constexpr double kMultiplier = 100.0;
        constexpr double kSeedDelta = 0.1;
        auto result = static_cast<uint8_t>(fabs(tan(seed)) * kMultiplier);
        seed += kSeedDelta;
        return result;
    }

  private:
    static constexpr double kInitialSeed = 106.0;
    double seed = kInitialSeed;
};

template <typename Iterator> inline void DeriveTEAKey(Iterator begin, Iterator end, const uint8_t *ekey)
{
    SimpleKey simple_key_generator{};

    for (; begin < end; begin++)
    {
        *begin++ = simple_key_generator.Next();
        if (begin < end)
        {
            *begin++ = *ekey++;
        }
    }
}

} // namespace parakeet_crypto::qmc::tea_key
