#pragma once

#include "tc_tea/tc_tea.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace parakeet_crypto::qmc2
{

class SimpleKeyGenerator
{
  private:
    static constexpr double kMultiplier = 100.0;
    static constexpr double kDelta = 0.1;
    double seed;

  public:
    SimpleKeyGenerator(uint8_t initial_seed) : seed(static_cast<double>(initial_seed) - kDelta)
    {
    }

    inline uint8_t Next()
    {
        seed += kDelta;
        return static_cast<uint8_t>(fabs(tan(seed)) * kMultiplier);
    }
};

class KeyEncryptionV1
{
  private:
    static constexpr std::size_t kPlaintextKeyPrefixLen = 8;
    static constexpr std::size_t kSimpleKeySize = 16;
    uint8_t seed_{0};

    std::array<uint8_t, kSimpleKeySize> GetTEAKey(const uint8_t *p_ekey) const
    {
        SimpleKeyGenerator simple_key_generator{seed_};
        std::array<uint8_t, kSimpleKeySize> tea_key{};
        for (auto it = tea_key.begin(); it < tea_key.end();) // NOLINT (readability-qualified-auto)
        {
            *it++ = simple_key_generator.Next();
            *it++ = *p_ekey++;
        }

        return tea_key;
    }

  public:
    KeyEncryptionV1(uint8_t initial_seed) : seed_(initial_seed)
    {
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> Decrypt(const std::vector<uint8_t> &cipher_key) const
    {
        if (cipher_key.size() < kPlaintextKeyPrefixLen)
        {
            return {};
        }

        auto tea_key = GetTEAKey(cipher_key.data());

        // Prepare for decryption...
        const auto *p_cipher = &cipher_key.at(kPlaintextKeyPrefixLen);
        size_t len = cipher_key.size() - kPlaintextKeyPrefixLen;

        std::vector<uint8_t> result(cipher_key.size());
        std::copy_n(cipher_key.begin(), kPlaintextKeyPrefixLen, result.begin());

        if (!tc_tea::CBC_Decrypt(&result.at(kPlaintextKeyPrefixLen), &len, p_cipher, len, tea_key.data()))
        {
            return {};
        }

        result.resize(kPlaintextKeyPrefixLen + len);
        return result;
    }

    [[nodiscard]] std::vector<uint8_t> Encrypt(const std::vector<uint8_t> &key_plain) const
    {
        if (key_plain.size() < kPlaintextKeyPrefixLen)
        {
            return {};
        }

        auto tea_key = GetTEAKey(key_plain.data());

        size_t plain_len = key_plain.size() - kPlaintextKeyPrefixLen;
        size_t cipher_len = tc_tea::CBC_GetEncryptedSize(plain_len);
        std::vector<uint8_t> result(cipher_len + kPlaintextKeyPrefixLen);
        std::copy_n(key_plain.cbegin(), kPlaintextKeyPrefixLen, result.begin());

        if (!tc_tea::CBC_Encrypt(&result.at(kPlaintextKeyPrefixLen), &cipher_len,  //
                                 &key_plain.at(kPlaintextKeyPrefixLen), plain_len, //
                                 tea_key.data()))
        {
            return {};
        }

        result.resize(cipher_len + kPlaintextKeyPrefixLen); // Should be the same size
        return result;
    }
};

} // namespace parakeet_crypto::qmc2
