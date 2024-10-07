#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/StreamHelper.h"
#include "parakeet-crypto/qmc2/footer_parser.h"
#include "parakeet-crypto/qmc2/key_util.h"
#include "parakeet-crypto/transformer/qmc.h"

#include "qmc2/rc4_crypto/qmc2_rc4_impl.h"
#include "qmc2/rc4_crypto/qmc2_segment.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

class QMC2DecryptionTransformer final : public ITransformer
{
  private:
    std::shared_ptr<qmc2::QMCFooterParser> footer_parser_{};
    std::vector<uint8_t> key_{};

  public:
    QMC2DecryptionTransformer(std::shared_ptr<qmc2::QMCFooterParser> footer_parser)
        : footer_parser_(std::move(footer_parser))
    {
    }

    QMC2DecryptionTransformer(std::shared_ptr<qmc2::QMCFooterParser> footer_parser, const uint8_t *key, size_t key_len)
        : QMC2DecryptionTransformer(std::move(footer_parser))
    {
        if (key != nullptr && key_len > 0)
        {
            key_.assign(key, key + key_len);
        }
    }

    const char *GetName() override
    {
        return "QMCv2 (MAP/RC4)";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        std::vector<uint8_t> key;
        size_t trim_size{0};
        auto parse_result = footer_parser_->Parse(*input);
        if (parse_result->state != qmc2::FooterParseState::OK)
        {
            // no key found, and no fallback key provided:
            if (key_.empty())
            {
                return TransformResult::ERROR_INVALID_FORMAT;
            }
        }
        if (parse_result->state == qmc2::FooterParseState::UnsupportedAndroidClientSTag ||
            parse_result->state == qmc2::FooterParseState::OK)
        {
            trim_size = parse_result->footer_size;
        }
        key = key_.empty() ? parse_result->key : key_;

        auto next_transformer = (qmc2::GetEncryptionType(key) == qmc2::QMC2EncryptionType::RC4)
                                    ? CreateQMC2RC4DecryptionTransformer(key)
                                    : CreateQMC2MapDecryptionTransformer(key);
        SlicedReadableStream reader{*input, 0, input->GetSize() - trim_size};
        return next_transformer->Transform(output, &reader);
    }
};

std::unique_ptr<ITransformer> CreateQMC2DecryptionTransformer(std::shared_ptr<qmc2::QMCFooterParser> footer_parser)
{
    return std::make_unique<QMC2DecryptionTransformer>(std::move(footer_parser));
}

std::unique_ptr<ITransformer> CreateQMC2DecryptionTransformer(std::shared_ptr<qmc2::QMCFooterParser> footer_parser,
                                                              const uint8_t *key, size_t key_len)
{
    return std::make_unique<QMC2DecryptionTransformer>(std::move(footer_parser), key, key_len);
}
} // namespace parakeet_crypto::transformer
