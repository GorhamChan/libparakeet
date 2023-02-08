#include "kuwo/kuwo_common.h"
#include "kuwo_common.h"
#include "parakeet-crypto/transformer/kuwo.h"

#include "parakeet-crypto/ITransformer.h"

#include "utils/EndianHelper.h"
#include "utils/PagedReader.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <cinttypes>
#include <cstdint>

#include <algorithm>
#include <array>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

class KuwoDecryptionTransformer : public ITransformer
{
  private:
    std::array<uint8_t, kKuwoDecryptionKeySize> key_{};

  public:
    KuwoDecryptionTransformer(const uint8_t *key) : ITransformer()
    {
        std::copy_n(key, kKuwoDecryptionKeySize, key_.begin());
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        KuwoHeaderUnion file_header{};
        if (!input->ReadExact(&file_header.as_bytes[0], sizeof(file_header)))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        if (!std::equal(kKnownKuwoHeader1.begin(), kKnownKuwoHeader1.end(), &file_header.as_header.header[0]) &&
            !std::equal(kKnownKuwoHeader2.begin(), kKnownKuwoHeader2.end(), &file_header.as_header.header[0]))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        std::array<uint8_t, kKuwoDecryptionKeySize> key{key_};
        auto resource_id = SwapLittleEndianToHost(file_header.as_header.resource_id);
        SetupKuwoDecryptionKey(resource_id, key_.begin(), key_.end());

        input->Seek(kFullKuwoHeaderLen, SeekDirection::FILE_BEGIN);

        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t offset, uint8_t *buffer, size_t n) {
            utils::XorFromOffset(buffer, n, this->key_.data(), this->key_.size(), offset);
            output->Write(buffer, n);
            return true;
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_OTHER;
    }
};

std::unique_ptr<ITransformer> CreateKuwoDecryptionTransformer(const uint8_t *key)
{
    return std::make_unique<KuwoDecryptionTransformer>(key);
}

} // namespace parakeet_crypto::transformer
