#pragma once
#include "ncm_rc4.h"
#include "parakeet-crypto/transformer/ncm.h"

#include <algorithm>
#include <optional>
#include <vector>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

namespace parakeet_crypto::transformer
{

static constexpr size_t kNCMFinalKeyLen = 0x100;
inline std::optional<std::array<uint8_t, kNCMFinalKeyLen>> DecryptNCMAudioKey(
    const std::vector<uint8_t> &file_key, std::array<uint8_t, kNCMContentKeySize> &aes_key)
{
    constexpr uint8_t kFileKeyXorKey{0x64};
    using AES = CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption;
    using Filter = CryptoPP::StreamTransformationFilter;

    std::vector<uint8_t> content_key;
    std::vector<uint8_t> file_key_mut(file_key.size());
    std::transform(file_key.cbegin(), file_key.cend(), file_key_mut.begin(),
                   [](auto key) { return key ^ kFileKeyXorKey; });

    try
    {
        AES aes(aes_key.data(), aes_key.size());
        Filter decryptor(aes, nullptr, Filter::PKCS_PADDING);
        decryptor.PutMessageEnd(file_key_mut.data(), file_key_mut.size());
        content_key.resize(decryptor.MaxRetrievable());
        decryptor.Get(content_key.data(), content_key.size());
    }
    catch (const CryptoPP::Exception &ex)
    {
        return {};
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
