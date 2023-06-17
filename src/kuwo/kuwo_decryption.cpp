#include "kuwo/kuwo_common.h"
#include "kuwo_common.h"
#include "parakeet-crypto/StreamHelper.h"
#include "parakeet-crypto/qmc2/key_util.h"
#include "parakeet-crypto/transformer/kuwo.h"

#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"

#include "utils/endian_helper.h"
#include "utils/loop_iterator.h"
#include "utils/paged_reader.h"
#include "utils/string_helper.h"
#include "utils/xor_helper.h"

#include <cinttypes>
#include <cstdint>

#include <algorithm>
#include <array>
#include <memory>
#include <utility>
#include <vector>

namespace parakeet_crypto::transformer
{

class KuwoDecryptionTransformer final : public ITransformer
{
  private:
    std::array<uint8_t, kKuwoDecryptionKeySize> key_{};
    std::vector<uint8_t> v2_key_{};

  public:
    KuwoDecryptionTransformer(const uint8_t *key) : KuwoDecryptionTransformer(key, std::vector<uint8_t>())
    {
    }
    KuwoDecryptionTransformer(const uint8_t *key, std::vector<uint8_t> v2_key)
        : ITransformer(), v2_key_(std::move(v2_key))
    {
        std::copy_n(key, kKuwoDecryptionKeySize, key_.begin());
    }

    const char *GetName() override
    {
        return "Kuwo (D)";
    }

    TransformResult TransformV1(uint64_t resource_id, IWriteable *output, IReadSeekable *input)
    {
        std::array<uint8_t, kKuwoDecryptionKeySize> key{};
        SetupKuwoDecryptionKey(key, key_, resource_id);

        input->Seek(kFullKuwoHeaderLen, SeekDirection::SEEK_FILE_BEGIN);

        utils::LoopIterator key_iter{key.data(), key.size(), input->GetOffset()};
        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t /*offset*/, uint8_t *buffer, size_t n) {
            std::for_each_n(buffer, n, [&](auto &value) { value ^= key_iter.GetAndMove(); });
            return output->Write(buffer, n);
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_OTHER;
    }

    TransformResult TransformV2(IWriteable *output, IReadSeekable *input)
    {
        auto next_transformer = qmc2::GetEncryptionType(v2_key_) == qmc2::QMC2EncryptionType::RC4
                                    ? CreateQMC2RC4DecryptionTransformer(v2_key_)
                                    : CreateQMC2MapDecryptionTransformer(v2_key_);

        input->Seek(kFullKuwoHeaderLen, SeekDirection::SEEK_FILE_BEGIN);
        SlicedReadableStream reader{*input, kFullKuwoHeaderLen, input->GetSize()};
        return next_transformer->Transform(output, &reader);
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

        switch (file_header.as_header.encryption_version)
        {
        case 1: {
            auto resource_id = SwapLittleEndianToHost(file_header.as_header.resource_id);
            return this->TransformV1(resource_id, output, input);
        }

        case 2:
            return this->TransformV2(output, input);

        default:
            return TransformResult::ERROR_NOT_IMPLEMENTED;
        }
    }
};

std::unique_ptr<ITransformer> CreateKuwoDecryptionTransformer(const uint8_t *key)
{
    return std::make_unique<KuwoDecryptionTransformer>(key);
}

std::unique_ptr<ITransformer> CreateKuwoDecryptionTransformer(const uint8_t *key, std::vector<uint8_t> v2_key)
{
    return std::make_unique<KuwoDecryptionTransformer>(key, std::move(v2_key));
}

} // namespace parakeet_crypto::transformer
