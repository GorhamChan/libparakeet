#include "KGMCrypto.h"
#include "utils/md5.h"

#include <algorithm>
#include <memory>

namespace parakeet_crypto::decryptor::kugou {

class KGMCryptoType3 : public KGMCrypto {
   private:
    std::array<uint8_t, 16> slot_key_;

    // file key is 17 bytes.
    // we are using a buffer of 32 bytes so we can let compiler to optimise.
    std::array<uint8_t, 32> file_key_;

    static inline std::array<uint8_t, 16> hash_type3(const std::span<const uint8_t> data) {
        std::array<uint8_t, 16> result;
        auto digest = utils::md5(data);
        // Reverse 2-bytes at a time.
        for (int i = 0; i < 16; i += 2) {
            result[i + 0] = digest[14 - i + 0];
            result[i + 1] = digest[14 - i + 1];
        }
        return result;
    }

   public:
    ~KGMCryptoType3() override = default;

    bool Configure(const KGMCryptoConfig& config,
                   const std::vector<uint8_t>& slot_key,
                   const kgm_file_header& header) override {
        slot_key_ = hash_type3(slot_key);

        auto file_key = hash_type3(header.key);
        std::copy_n(file_key.begin(), file_key.size(), file_key_.begin());
        file_key_[16] = 0x6b;
        // fill the rest of file_key... 15 bytes
        std::copy_n(file_key.begin(), 15, file_key_.begin() + 17);

        return true;
    }

    void Encrypt(uint64_t offset, std::span<uint8_t> buffer) override {
        std::ranges::transform(buffer.begin(), buffer.end(), buffer.begin(), [&offset, this](auto v) {
            uint8_t offset_key = xor_u32_bytes(static_cast<uint32_t>(offset));
            uint8_t slot_key = slot_key_[offset % slot_key_.size()];
            uint8_t file_key = file_key_[offset % file_key_.size()];

            v ^= offset_key;
            v ^= slot_key;
            v ^= v << 4;
            v ^= file_key;

            offset++;
            return v;
        });
    }

    void Decrypt(uint64_t offset, std::span<uint8_t> buffer) override {
        std::ranges::transform(buffer.begin(), buffer.end(), buffer.begin(), [&offset, this](auto v) {
            uint8_t offset_key = xor_u32_bytes(static_cast<uint32_t>(offset));
            uint8_t slot_key = slot_key_[offset % slot_key_.size()];
            uint8_t file_key = file_key_[offset % file_key_.size()];

            v ^= file_key;
            v ^= v << 4;
            v ^= slot_key;
            v ^= offset_key;

            offset++;
            return v;
        });
    }
};

std::unique_ptr<KGMCrypto> CreateKGMCryptoType3() {
    return std::make_unique<KGMCryptoType3>();
}

}  // namespace parakeet_crypto::decryptor::kugou
