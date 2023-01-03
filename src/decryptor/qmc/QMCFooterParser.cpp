#include "parakeet-crypto/decryptor/qmc/QMCFooterParser.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"

#include <algorithm>

using parakeet_crypto::utils::ParseCSVLine;

namespace parakeet_crypto::misc::tencent {

namespace detail {

constexpr uint32_t kMagicQTag = 0x51546167;  // 'QTag'
constexpr uint32_t kMagicSTag = 0x53546167;  // 'STag'

class QMCFooterParserImpl : public QMCFooterParser {
   public:
    QMCFooterParserImpl(std::shared_ptr<QMCKeyDeriver> key_deriver) : key_deriver_(key_deriver){};

    std::unique_ptr<QMCFooterParseResult> Parse(const uint8_t* p_in, std::size_t len) const override {
        if (len < 4) return nullptr;

        auto eof = ReadBigEndian<uint32_t>(&p_in[len - 4]);

        // Current (2022.04) android format, does not include embedded keys.
        if (eof == kMagicSTag) return nullptr;

        std::unique_ptr<QMCFooterParseResult> result;
        if (eof == kMagicQTag) {
            // Legacy android format, with embedded metadata & keys.
            result = ParseAndroidQTagFile(p_in, len);
        } else {
            // Windows client, end with meta size.
            result = ParseWindowsEncryptedFile(p_in, len);
        }

        // Parse Key from EKey OK
        if (result) {
            key_deriver_->FromEKey(result->key, result->ekey_b64);
        }

        return result;
    }

    inline std::unique_ptr<QMCFooterParseResult> ParseAndroidQTagFile(const uint8_t* p_in, std::size_t len) const {
        // Legacy Android format.
        //   metadata := [ansi ekey_b64] ","
        //               [ansi songid] ","
        //               [ansi metadata_version '2']
        //   eof_mark := [(be)uint32_t meta_len] [bytes 'QTag']
        //   qmc_file := [encrypted_data] [metadata] [eof_mark]
        //
        // Where:
        //   meta_len := bytes( [metadata] [eof_mark] ).size()
        if (len < 8) return nullptr;

        auto meta_len = ReadBigEndian<uint32_t>(&p_in[len - 8]);

        size_t required_len = meta_len + 8;
        if (len < required_len) return nullptr;

        auto result = std::make_unique<QMCFooterParseResult>();
        result->eof_bytes_ignore = required_len;

        auto metadata = ParseCSVLine(&p_in[len - 8 - meta_len], meta_len);

        // We should see the following:
        //    ekey_b64, song id and metadata version;
        // where metadata version should be '2'.
        if (metadata.size() != 3 || metadata[2] != "2") return nullptr;

        result->ekey_b64 = metadata[0];
        return result;
    }

    inline std::unique_ptr<QMCFooterParseResult> ParseWindowsEncryptedFile(const uint8_t* p_in, std::size_t len) const {
        // Legacy PC QQMusic encoded format.
        // ekey_b64 := [ansi ekey_b64]
        // eof_mark := [(le)uint32_t ekey_size]
        // qmc_file := [encrypted_data] [ekey_b64] [eof_mark]
        if (len < 4) return nullptr;

        auto ekey_size = ReadLittleEndian<uint32_t>(&p_in[len - 4]);

        size_t required_len = ekey_size + 4;
        if (len < required_len) return nullptr;

        auto result = std::make_unique<QMCFooterParseResult>();
        result->eof_bytes_ignore = required_len;

        const uint8_t* eof_ekey = &p_in[len - 4];
        const std::string ekey_b64 = std::string(eof_ekey - ekey_size, eof_ekey);

        result->ekey_b64 = ekey_b64;
        return result;
    }

   private:
    std::shared_ptr<QMCKeyDeriver> key_deriver_;
};

}  // namespace detail

std::unique_ptr<QMCFooterParser> QMCFooterParser::Create(std::shared_ptr<QMCKeyDeriver> key_deriver) {
    return std::make_unique<detail::QMCFooterParserImpl>(key_deriver);
}

}  // namespace parakeet_crypto::misc::tencent
