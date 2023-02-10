#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"
#include "qmc2/rc4_crypto/qmc2_rc4_impl.h"
#include "qmc2/rc4_crypto/qmc2_segment.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

constexpr size_t kFirstSegmentSize{0x0080};
constexpr size_t kOtherSegmentSize{0x1400};
constexpr size_t kSegmentSize{kOtherSegmentSize}; // Pick the largest one

static_assert(kSegmentSize >= kFirstSegmentSize);
static_assert(kSegmentSize >= kOtherSegmentSize);

class QMC2RC4DecryptionTransformer final : public ITransformer
{
  private:
    std::vector<uint8_t> key_{};
    std::vector<uint8_t> rc4_state_{};
    qmc2_rc4::SegmentKeyImpl segment_key_;

    inline void ProcessFirstSegment(uint8_t *buffer, size_t buffer_len)
    {
        auto key_len = key_.size();
        for (size_t i = 0; i < buffer_len; i++)
        {
            auto seed = key_[i % key_len];
            auto next_index = segment_key_.GetKey(i, seed) % key_len;
            buffer[i] ^= key_[next_index];
        }
    }

    inline void ProcessOtherSegment(size_t offset, uint32_t segment_id, uint8_t *buffer, size_t buffer_len)
    {
        // 511: equivalent to "% 512". QM had this value hardcoded.
        constexpr size_t kKeyIndexMask = 0x1FF;

        auto seed = key_[segment_id & kKeyIndexMask];
        auto inital_discard = segment_key_.GetKey(segment_id, seed) & kKeyIndexMask;
        auto discard_count = static_cast<uint32_t>(offset + inital_discard);

        qmc2_rc4::RC4 rc4{rc4_state_, discard_count};
        for (size_t i = 0; i < buffer_len; i++)
        {
            buffer[i] ^= rc4.Next();
        }
    }

  public:
    QMC2RC4DecryptionTransformer(const uint8_t *key, size_t key_len)
        : segment_key_(qmc2_rc4::SegmentKeyImpl{key, key_len}), key_{key, key + key_len},
          rc4_state_(qmc2_rc4::RC4::CreateStateFromKey(key, key_len))
    {
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        std::array<uint8_t, kSegmentSize> buffer{};

        { // Process first segment
            size_t bytes_read = input->Read(buffer.data(), kFirstSegmentSize);
            if (bytes_read == 0)
            {
                return TransformResult::OK;
            }

            ProcessFirstSegment(buffer.data(), bytes_read);
            output->Write(buffer.data(), bytes_read);
        }

        { // Finish first segment.
            size_t bytes_read = input->Read(buffer.data(), kOtherSegmentSize - kFirstSegmentSize);
            if (bytes_read == 0)
            {
                return TransformResult::OK;
            }

            ProcessOtherSegment(kFirstSegmentSize, 0, buffer.data(), bytes_read);
            output->Write(buffer.data(), bytes_read);
        }

        for (uint32_t segment_id = 1; true; segment_id++)
        {
            size_t bytes_read = input->Read(buffer.data(), kOtherSegmentSize);
            if (bytes_read == 0)
            {
                return TransformResult::OK;
            }

            ProcessOtherSegment(0, segment_id, buffer.data(), bytes_read);
            output->Write(buffer.data(), bytes_read);
        }

        return TransformResult::OK;
    }
};

std::unique_ptr<ITransformer> CreateQMC2RC4DecryptionTransformer(const uint8_t *key, size_t key_len)
{
    return std::make_unique<QMC2RC4DecryptionTransformer>(key, key_len);
}

} // namespace parakeet_crypto::transformer
