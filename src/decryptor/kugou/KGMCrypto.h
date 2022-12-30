#pragma once

#include "KGMHeaderStruct.h"

#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <vector>

namespace parakeet_crypto::decryptor::kugou {

struct KGMCryptoConfig {
    std::map<uint32_t, std::vector<uint8_t>> slot_keys;
    std::vector<uint8_t> v4_slot_key_expansion_table;
    std::vector<uint8_t> v4_file_key_expansion_table;
};

inline uint8_t xor_u32_bytes(uint32_t value) {
    uint32_t x = value;
    x ^= x >> 16;
    x ^= x >> 8;
    return static_cast<uint8_t>(x);
}

class KGMCrypto {
   public:
    virtual ~KGMCrypto() = default;
    virtual bool Configure(const KGMCryptoConfig& config,
                           const std::vector<uint8_t>& slot_key,
                           const kgm_file_header& header) = 0;
    virtual void Encrypt(uint64_t offset, std::span<uint8_t> buffer) = 0;
    virtual void Decrypt(uint64_t offset, std::span<uint8_t> buffer) = 0;
};

std::unique_ptr<KGMCrypto> CreateKGMCrypto(const kgm_file_header& header, const KGMCryptoConfig& config);
std::unique_ptr<KGMCrypto> CreateKGMDecryptor(const kgm_file_header& header, const KGMCryptoConfig& config);

std::unique_ptr<KGMCrypto> CreateKGMCryptoType2();
std::unique_ptr<KGMCrypto> CreateKGMCryptoType3();
std::unique_ptr<KGMCrypto> CreateKGMCryptoType4();

// Copy-paste of decryptor definitions...

}  // namespace parakeet_crypto::decryptor::kugou
