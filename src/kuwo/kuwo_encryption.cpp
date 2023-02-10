#include "kuwo_common.h"

#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/kuwo.h"

#include "utils/endian_helper.h"
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

class KuwoEncryptionTransformer : public ITransformer
{
  private:
    uint64_t resource_id_{};
    std::array<uint8_t, kKuwoDecryptionKeySize> key_{};

  public:
    KuwoEncryptionTransformer(const uint8_t *key, uint64_t resource_id) : ITransformer(), resource_id_(resource_id)
    {
        std::copy_n(key, kKuwoDecryptionKeySize, key_.begin());
        SetupKuwoDecryptionKey(resource_id, key_.begin(), key_.end());
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        std::array<uint8_t, kFullKuwoHeaderLen> buffer{};
        KuwoHeader hdr{};
        std::copy(kKnownKuwoHeader2.begin(), kKnownKuwoHeader2.end(), &hdr.header[0]);
        hdr.resource_id = SwapHostToLittleEndian(resource_id_);
        std::memcpy(buffer.data(), &hdr, sizeof(hdr));
        output->Write(buffer.data(), buffer.size());

        auto encrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t offset, uint8_t *buffer, size_t n) {
            utils::XorFromOffset(buffer, n, key_.data(), key_.size(), offset);
            output->Write(buffer, n);
            return true;
        });

        return encrypt_ok ? TransformResult::OK : TransformResult::ERROR_OTHER;
    }
};

std::unique_ptr<ITransformer> CreateKuwoEncryptionTransformer(const uint8_t *key, uint64_t resource_id)
{
    return std::make_unique<KuwoEncryptionTransformer>(key, resource_id);
}

} // namespace parakeet_crypto::transformer
