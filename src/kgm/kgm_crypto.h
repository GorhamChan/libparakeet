#pragma once

#include "kgm/kgm_constants.h"
#include "kgm_header.h"

#include "parakeet-crypto/transformer/kgm.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>

namespace parakeet_crypto::kgm
{

inline uint8_t xor_u32_bytes(uint32_t value)
{
    return static_cast<uint8_t>((value >> 24) ^ (value >> 16) ^ (value >> 8) ^ value); // NOLINT(*-magic-numbers)
}

enum class Mode
{
    KGM = 0,
    VPR = 0,
};

class IKGMCrypto
{
  public:
    virtual ~IKGMCrypto() = default;
    virtual bool Configure(const transformer::KGMConfig &config, const std::vector<uint8_t> &slot_key,
                           const FileHeader &header) = 0;

    virtual void Decrypt(uint64_t offset, uint8_t *buffer, size_t len) = 0;
    virtual void Encrypt(uint64_t offset, uint8_t *buffer, size_t len) = 0;
};

std::unique_ptr<IKGMCrypto> CreateKGMCryptoType2();
std::unique_ptr<IKGMCrypto> CreateKGMCryptoType3();
std::unique_ptr<IKGMCrypto> CreateKGMCryptoType4();

inline std::unique_ptr<IKGMCrypto> CreateKGMCrypto(const FileHeader &header, const transformer::KGMConfig &config)
{
    auto slot_key_it = config.slot_keys.find(header.key_slot);
    if (slot_key_it == config.slot_keys.end())
    {
        return nullptr;
    }

    auto kgm_crypto = ([&]() {
        switch (header.crypto_version)
        {
        case 2:
            return CreateKGMCryptoType2();
        case 3:
            return CreateKGMCryptoType3();
        case 4:
            return CreateKGMCryptoType4();
        default:
            return std::unique_ptr<IKGMCrypto>{};
        }
    })();

    if (kgm_crypto && kgm_crypto->Configure(config, slot_key_it->second, header))
    {
        return kgm_crypto;
    }

    return nullptr;
}

inline std::unique_ptr<IKGMCrypto> CreateKGMDecryptionCrypto(const FileHeader &header,
                                                             const transformer::KGMConfig &config)
{
    Mode mode{Mode::KGM};
    if (IsKGMHeader(&header.magic_header[0]))
    {
        mode = Mode::KGM;
    }
    else if (IsVPRHeader(&header.magic_header[0]))
    {
        mode = Mode::VPR;
    }
    else
    {
        return nullptr;
    }

    auto kgm_crypto = CreateKGMCrypto(header, config);
    if (!kgm_crypto)
    {
        return nullptr;
    }

    std::array<uint8_t, sizeof(header.decryption_test_data)> test_data{};
    std::copy_n(&header.decryption_test_data[0], sizeof(header.decryption_test_data), test_data.begin());
    kgm_crypto->Decrypt(0, test_data.data(), test_data.size());

    auto decryption_ok = mode == Mode::KGM //
                             ? IsKGMTestDataPlain(test_data.data())
                             : IsVPRTestDataPlain(test_data.data());
    if (!decryption_ok)
    {
        return nullptr;
    }

    return kgm_crypto;
}

} // namespace parakeet_crypto::kgm
