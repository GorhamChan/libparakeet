
#include "parakeet-crypto/ITransformer.h"
#include "utils/PagedReader.h"
#include "utils/XorHelper.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::transformer
{

class QMC1StaticDecryptionTransformer : public ITransformer
{
  private:
    static constexpr size_t kQMC1KeySize = 128;
    static constexpr size_t kCipherPageSize = 0x7fff;

    std::array<uint8_t, kQMC1KeySize> key_{};

  public:
    QMC1StaticDecryptionTransformer(const uint8_t *key) : ITransformer()
    {
        std::copy_n(key, key_.size(), key_.begin());
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t offset, uint8_t *buffer, size_t n) {
            utils::XorBlockFromOffset(buffer, n, kCipherPageSize, key_.data(), key_.size(), offset);

            // Off-by-1 fix at the first page.
            if (offset < kCipherPageSize && kCipherPageSize < (offset + n))
            {
                auto boundary_index = kCipherPageSize - offset;
                buffer[boundary_index] ^= key_[kCipherPageSize % key_.size()] ^ key_[0];
            }

            output->Write(buffer, n);
            return true;
        });

        return TransformResult::OK;
    }
};

} // namespace parakeet_crypto::transformer
