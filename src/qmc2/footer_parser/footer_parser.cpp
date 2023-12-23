#include "parakeet-crypto/qmc2/footer_parser.h"
#include "footer_parser_android.h"
#include "footer_parser_pc.h"

#include "qmc2/footer_parser/footer_parser_pc_v2.h"
#include "utils/endian_helper.h"

#include <memory>
#include <utility>

namespace parakeet_crypto::qmc2
{

class QMCFooterParserImpl : public QMCFooterParser
{
  private:
    std::shared_ptr<IKeyCrypto> key_crypto_;
    static constexpr size_t kMinimumFooterLen = sizeof(QQMusicTagMusicExTail);

  public:
    QMCFooterParserImpl(std::shared_ptr<IKeyCrypto> key_crypto) : QMCFooterParser(), key_crypto_(std::move(key_crypto))
    {
    }

    std::unique_ptr<FooterParseResult> Parse(const uint8_t *file_footer, size_t len) override
    {
        if (len < kMinimumFooterLen)
        {
            return std::make_unique<FooterParseResult>(FooterParseState::NeedMoreBytes, kMinimumFooterLen);
        }

        const auto *magic_u32 = &file_footer[len - sizeof(uint32_t)];
        if (FooterParserAndroid::IsUnsupportedAndroidSTag(magic_u32))
        {
            auto footer_size = ReadBigEndian<uint32_t>(magic_u32 - sizeof(uint32_t)) + sizeof(uint32_t) * 2;
            return std::make_unique<FooterParseResult>(FooterParseState::UnsupportedAndroidClientSTag, footer_size);
        }

        if (FooterParserAndroid::IsAndroidQTag(magic_u32))
        {
            return FooterParserAndroid(key_crypto_).Parse(file_footer, len);
        }

        if (FooterParserPC::IsPCFooter(magic_u32))
        {
            return FooterParserPC(key_crypto_).Parse(file_footer, len);
        }

        const auto *tail_music_ex =
            // NOLINTNEXTLINE(*-reinterpret-cast)
            reinterpret_cast<const QQMusicTagMusicExTail *>(&file_footer[len - sizeof(QQMusicTagMusicExTail)]);
        if (FooterParserPCMusicEx::IsPCMusicExFooter(tail_music_ex))
        {
            return FooterParserPCMusicEx::Parse(file_footer, len);
        }

        return std::make_unique<FooterParseResult>(FooterParseState::UnknownContent);
    }
};

std::unique_ptr<QMCFooterParser> CreateQMC2FooterParser(std::shared_ptr<IKeyCrypto> key_crypto)
{
    return std::make_unique<QMCFooterParserImpl>(std::move(key_crypto));
}

} // namespace parakeet_crypto::qmc2
