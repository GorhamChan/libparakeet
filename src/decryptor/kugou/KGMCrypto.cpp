#include "KGMCrypto.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace parakeet_crypto::decryptor::kugou
{

std::unique_ptr<KGMCrypto> CreateKGMCrypto(const kgm_file_header &header, const KGMCryptoConfig &config)
{
    auto slot_key_it = config.slot_keys.find(header.key_slot);
    if (slot_key_it == config.slot_keys.end())
    {
        return nullptr;
    }

    std::unique_ptr<KGMCrypto> kgm_crypto;

    switch (header.encryption_type)
    {
    case 2:
        kgm_crypto = CreateKGMCryptoType2();
        break;
    case 3:
        kgm_crypto = CreateKGMCryptoType3();
        break;
    case 4:
        kgm_crypto = CreateKGMCryptoType4();
        break;

    default:
        return nullptr;
    }

    if (!kgm_crypto->Configure(config, slot_key_it->second, header))
    {
        return nullptr;
    }

    return kgm_crypto;
}

enum class KGMType
{
    kUnknown = 0,
    kKGM,
    kVPR
};

KGMType DetectKGMType(std::span<const uint8_t, 16> header_magic)
{
    const static std::array<const uint8_t, 16> kKGMFileMagic = {
        0x7c, 0xd5, 0x32, 0xeb, 0x86, 0x02, 0x7f, 0x4b, 0xa8, 0xaf, 0xa6, 0x8e, 0x0f, 0xff, 0x99, 0x14,
    };

    const static std::array<const uint8_t, 16> kVPRFileMagic = {
        0x05, 0x28, 0xbc, 0x96, 0xe9, 0xe4, 0x5a, 0x43, 0x91, 0xaa, 0xbd, 0xd0, 0x7a, 0xf5, 0x36, 0x31,
    };

    if (std::equal(kKGMFileMagic.begin(), kKGMFileMagic.end(), header_magic.begin()))
    {
        return KGMType::kKGM;
    }
    else if (std::equal(kVPRFileMagic.begin(), kVPRFileMagic.end(), header_magic.begin()))
    {
        return KGMType::kVPR;
    }
    else
    {
        return KGMType::kUnknown;
    }
}

std::unique_ptr<KGMCrypto> CreateKGMDecryptor(const kgm_file_header &header, const KGMCryptoConfig &config)
{
    KGMType kgm_type = DetectKGMType(header.magic);
    if (kgm_type == KGMType::kUnknown)
        return nullptr;

    auto kgm_crypto = CreateKGMCrypto(header, config);
    if (!kgm_crypto)
    {
        return nullptr;
    }

    // Validate the file key.
    auto response = std::to_array(header.key_challenge);
    kgm_crypto->Decrypt(0, response);

    const static std::array<const uint8_t, 16> kKGMChallengeBytes = {
        0x38, 0x85, 0xED, 0x92, 0x79, 0x5F, 0xF8, 0x4C, 0xB3, 0x03, 0x61, 0x41, 0x16, 0xA0, 0x1D, 0x47,
    };

    const static std::array<const uint8_t, 16> kVPRChallengeBytes = {
        0x1D, 0x5A, 0x05, 0x34, 0x0C, 0x41, 0x8D, 0x42, 0x9C, 0x83, 0x92, 0x6C, 0xAE, 0x16, 0xFE, 0x56,
    };

    bool challenge_ok = false;
    if (kgm_type == KGMType::kKGM)
    {
        challenge_ok = std::equal(response.begin(), response.end(), kKGMChallengeBytes.begin());
    }
    else if (kgm_type == KGMType::kVPR)
    {
        challenge_ok = std::equal(response.begin(), response.end(), kVPRChallengeBytes.begin());
    }

    if (!challenge_ok)
    {
        return nullptr;
    }

    return kgm_crypto;
}

} // namespace parakeet_crypto::decryptor::kugou
