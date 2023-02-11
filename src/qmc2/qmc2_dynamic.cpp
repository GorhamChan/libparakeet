#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/StreamHelper.h"
#include "parakeet-crypto/qmc2/footer_parser.h"
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

  public:
    QMC2DecryptionTransformer(std::shared_ptr<qmc2::QMCFooterParser> footer_parser)
        : footer_parser_(std::move(footer_parser))
    {
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        auto parse_result = footer_parser_->Parse(*input);
        if (parse_result->state != qmc2::FooterParseState::OK)
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        auto key_size = parse_result->key.size();

        constexpr size_t kQMC2UseRC4Boundary = 300;
        auto next_transformer = (key_size >= kQMC2UseRC4Boundary) //
                                    ? CreateQMC2RC4DecryptionTransformer(parse_result->key)
                                    : CreateQMC2MapDecryptionTransformer(parse_result->key);
        SlicedReadableStream reader{*input, 0, input->GetSize() - parse_result->footer_size};
        return next_transformer->Transform(output, &reader);
    }
};

std::unique_ptr<ITransformer> CreateQMC2DecryptionTransformer(std::shared_ptr<qmc2::QMCFooterParser> footer_parser)
{
    return std::make_unique<QMC2DecryptionTransformer>(std::move(footer_parser));
}

} // namespace parakeet_crypto::transformer
