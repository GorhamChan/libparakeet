#include "kgm_crypto.h"
#include <algorithm>
#include <cstdint>
#include <memory>

namespace parakeet_crypto::kgm
{

class KGMCryptoType2 final : public IKGMCrypto
{
  private:
    // provide a fixed size of 4 to let compiler optimise
    std::array<uint8_t, 4> key_{};

  public:
    bool Configure(const transformer::KGMConfig & /*config*/, const std::vector<uint8_t> &slot_key,
                   const FileHeader & /*header*/) override
    {
        if (slot_key.size() < key_.size())
        {
            return false;
        }

        std::copy_n(slot_key.begin(), key_.size(), key_.begin());
        return true;
    }

    template <bool IS_ENCRYPT> void EncryptDecrypt(uint64_t offset, uint8_t *buffer, size_t len)
    {
        auto *end = buffer + len;
        for (auto *it = buffer; it < end; it++)
        {
            uint8_t key = key_[offset % key_.size()];

            auto v = *it; // NOLINT(readability-identifier-length)
            if constexpr (IS_ENCRYPT)
            {
                v ^= key;
                v ^= v << 4;
            }
            else
            {
                v ^= v << 4;
                v ^= key;
            }
            *it = v;

            offset++;
        }
    }

    void Encrypt(uint64_t offset, uint8_t *buffer, size_t len) override
    {
        EncryptDecrypt<true>(offset, buffer, len);
    }

    void Decrypt(uint64_t offset, uint8_t *buffer, size_t len) override
    {
        EncryptDecrypt<false>(offset, buffer, len);
    }
};

std::unique_ptr<IKGMCrypto> CreateKGMCryptoType2()
{
    return std::make_unique<KGMCryptoType2>();
}

} // namespace parakeet_crypto::kgm
