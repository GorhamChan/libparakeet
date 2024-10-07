#pragma once

#include "parakeet-crypto/utils/base64.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <optional>
#include <tc_tea/tc_tea.h>
#include <vector>

namespace parakeet_crypto::qmc2
{

class KeyEncryptionV2
{
  private:
    static constexpr std::array<const uint8_t, 18> kEncV2Prefix = {
        0x51, 0x51, 0x4D, 0x75, 0x73, 0x69, 0x63, 0x20, 0x45, 0x6E, 0x63, 0x56, 0x32, 0x2C, 0x4B, 0x65, 0x79, 0x3A};

    const uint8_t *key_1_;
    const uint8_t *key_2_;

  public:
    KeyEncryptionV2(const uint8_t *key_1, const uint8_t *key_2) : key_1_(key_1), key_2_(key_2)
    {
    }

    static bool IsEncV2(const uint8_t *key)
    {
        return std::equal(kEncV2Prefix.begin(), kEncV2Prefix.end(), key);
    }

    std::optional<std::vector<uint8_t>> Decrypt(const std::vector<uint8_t> &cipher)
    {
        std::vector<uint8_t> key(cipher.cbegin() + kEncV2Prefix.size(), cipher.cend());
        key = tc_tea::CBC_Decrypt(key, key_1_);
        key = tc_tea::CBC_Decrypt(key, key_2_);
        if (key.empty())
        {
            return {};
        }
        return utils::Base64Decode(key.data(), key.size());
    }

    std::vector<uint8_t> Encrypt(const std::vector<uint8_t> &plain)
    {
        auto &GetEncryptedSize = tc_tea::CBC_GetEncryptedSize;

        std::vector<uint8_t> key = utils::Base64Encode(plain.data(), plain.size());
        key = tc_tea::CBC_Encrypt(key, key_2_);
        key = tc_tea::CBC_Encrypt(key, key_1_);
        key.insert(key.begin(), kEncV2Prefix.begin(), kEncV2Prefix.end());
        return key;
    }
};

} // namespace parakeet_crypto::qmc2
