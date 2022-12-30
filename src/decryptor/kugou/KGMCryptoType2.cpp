#include "KGMCrypto.h"

#include <algorithm>
#include <cassert>
#include <memory>

namespace parakeet_crypto::decryptor::kugou {

class KGMCryptoType2 : public KGMCrypto {
   private:
    // provide a fixed size of 4 to let compiler optimise
    std::array<uint8_t, 4> key_;

   public:
    ~KGMCryptoType2() override = default;

    bool Configure(const KGMCryptoConfig& config,
                   const std::vector<uint8_t>& slot_key,
                   const kgm_file_header& header) override {
        assert(slot_key.size() == key_.size());
        std::ranges::copy(slot_key.begin(), slot_key.end(), key_.begin());
        return true;
    }

    void Encrypt(uint64_t offset, std::span<uint8_t> buffer) override {
        std::ranges::transform(buffer.begin(), buffer.end(), buffer.begin(), [&offset, this](auto v) {
            uint8_t key = key_[offset % key_.size()];

            v ^= key;
            v ^= v << 4;

            offset++;
            return v;
        });
    }

    void Decrypt(uint64_t offset, std::span<uint8_t> buffer) override {
        std::ranges::transform(buffer.begin(), buffer.end(), buffer.begin(), [&offset, this](auto v) {
            uint8_t key = key_[offset % key_.size()];

            v ^= v << 4;
            v ^= key;

            offset++;
            return v;
        });
    }
};

std::unique_ptr<KGMCrypto> CreateKGMCryptoType2() {
    return std::make_unique<KGMCryptoType2>();
}

}  // namespace parakeet_crypto::decryptor::kugou
