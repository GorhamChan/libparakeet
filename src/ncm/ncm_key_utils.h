#pragma once
#include "ncm_rc4.h"
#include "parakeet-crypto/transformer/ncm.h"
#include "utils/pkcs7.hpp"

#include <algorithm>
#include <optional>
#include <vector>

#include "parakeet-crypto/utils/aes.h"

namespace parakeet_crypto::transformer
{

static constexpr size_t kNCMFinalKeyLen = 0x100;
inline std::optional<std::array<uint8_t, kNCMFinalKeyLen>> DecryptNCMAudioKey(
    std::vector<uint8_t> &file_key, const std::array<uint8_t, kNCMContentKeySize> &aes_key)
{
    constexpr uint8_t kFileKeyXorKey{0x64};

    std::vector<uint8_t> content_key(file_key.size());
    std::transform(file_key.cbegin(), file_key.cend(), content_key.begin(),
                   [&](auto key) { return key ^ kFileKeyXorKey; });
    auto aes_decrypt = aes::make_aes_128_ecb_decryptor(aes_key.data());
    if (!aes_decrypt->process(content_key))
    {
        return {}; // invalid data size
    }

    if (!utils::PKCS7_unpad<kNCMContentKeySize, decltype(content_key) &>(content_key))
    {
        return {}; // invalid padding
    }

    constexpr static std::array<const uint8_t, 17> kContentKeyPrefix{'n', 'e', 't', 'e', 'a', 's', 'e', 'c', 'l',
                                                                     'o', 'u', 'd', 'm', 'u', 's', 'i', 'c'};

    if (!std::equal(kContentKeyPrefix.cbegin(), kContentKeyPrefix.cend(), content_key.cbegin()))
    {
        return {};
    }

    NeteaseRC4 rc4(&content_key.at(kContentKeyPrefix.size()), content_key.size() - kContentKeyPrefix.size());
    std::array<uint8_t, kNCMFinalKeyLen> key{};
    for (auto it = key.begin(); it < key.end(); it++) // NOLINT(readability-qualified-auto)
    {
        *it = rc4.Next();
    }

    return key;
}

} // namespace parakeet_crypto::transformer
