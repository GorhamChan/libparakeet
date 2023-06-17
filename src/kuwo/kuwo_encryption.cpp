#include "kuwo_common.h"

#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/kuwo.h"

#include "utils/endian_helper.h"
#include "utils/loop_iterator.h"
#include "utils/paged_reader.h"
#include "utils/string_helper.h"
#include "utils/xor_helper.h"

#include <cinttypes>
#include <cstdint>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

class KuwoEncryptionTransformer final : public ITransformer
{
  private:
    uint32_t resource_id_{};
    std::array<uint8_t, kKuwoDecryptionKeySize> key_{};

  public:
    KuwoEncryptionTransformer(const uint8_t *key, uint32_t resource_id) : ITransformer(), resource_id_(resource_id)
    {
        std::copy_n(key, kKuwoDecryptionKeySize, key_.begin());
        SetupKuwoDecryptionKey(key_, key_, resource_id);
    }

    const char *GetName() override
    {
        return "Kuwo (E)";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        std::array<uint8_t, kFullKuwoHeaderLen> buffer{};
        KuwoHeader hdr{};
        hdr.encryption_version = SwapHostToLittleEndian(1);
        std::copy(kKnownKuwoHeader2.begin(), kKnownKuwoHeader2.end(), &hdr.header[0]);
        hdr.resource_id = SwapHostToLittleEndian(resource_id_);
        std::memcpy(buffer.data(), &hdr, sizeof(hdr));
        if (!output->Write(buffer.data(), buffer.size()))
        {
            return TransformResult::ERROR_IO_OUTPUT_UNKNOWN;
        }

        utils::LoopIterator key_iter{key_.data(), key_.size(), input->GetOffset()};
        auto encrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t /*offset*/, uint8_t *buffer, size_t n) {
            std::for_each_n(buffer, n, [&](auto &value) { value ^= key_iter.GetAndMove(); });
            return output->Write(buffer, n);
        });

        return encrypt_ok ? TransformResult::OK : TransformResult::ERROR_IO_OUTPUT_UNKNOWN;
    }
};

std::unique_ptr<ITransformer> CreateKuwoEncryptionTransformer(const uint8_t *key, uint32_t resource_id)
{
    return std::make_unique<KuwoEncryptionTransformer>(key, resource_id);
}

} // namespace parakeet_crypto::transformer
