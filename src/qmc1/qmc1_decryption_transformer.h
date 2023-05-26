
#include "parakeet-crypto/ITransformer.h"
#include "utils/loop_iterator.h"
#include "utils/paged_reader.h"
#include "utils/xor_helper.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::transformer
{

class QMC1StaticDecryptionTransformer final : public ITransformer
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

    const char *GetName() override
    {
        return "QMCv1";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        utils::LoopIterator key_iter{key_.data(), key_.size(), 0};
        utils::LoopCounter counter{kCipherPageSize, 0};
        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t offset, uint8_t *buffer, size_t n) {
            std::for_each_n(buffer, n, [&](auto &value) {
                value ^= key_iter.GetAndMove();

                // Reaches page boundary
                if (counter.Next())
                {
                    key_iter.Reset();
                }
            });

            // Off-by-1 fix at the first page.
            if (offset < kCipherPageSize && kCipherPageSize < (offset + n))
            {
                auto boundary_index = kCipherPageSize - offset;
                buffer[boundary_index] ^= key_[kCipherPageSize % key_.size()] ^ key_[0];
            }

            return output->Write(buffer, n);
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_INSUFFICIENT_OUTPUT;
    }
};

} // namespace parakeet_crypto::transformer
