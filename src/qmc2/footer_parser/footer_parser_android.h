#pragma once

#include "parakeet-crypto/qmc2/footer_parser.h"
#include "parakeet-crypto/qmc2/key_crypto.h"
#include "utils/EndianHelper.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <memory>
#include <utility>

namespace parakeet_crypto::qmc2
{

// Legacy Android format.
//   metadata := [ansi ekey_b64] ","
//               [ansi song_id] ","
//               [ansi metadata_version '2']
//   eof_mark := [(be)uint32_t meta_len] [bytes 'QTag']
//   qmc_file := [encrypted_data] [metadata] [eof_mark]
//
// Where:
//   meta_len := bytes( [metadata] ).size()
class FooterParserAndroid
{
  private:
    std::shared_ptr<IKeyCrypto> key_crypto_;
    template <typename Iterator> inline Iterator FindComma(Iterator begin, Iterator end)
    {
        for (auto it = begin; it < end; it++)
        {
            if (*it == ',')
            {
                return it;
            }
        }
        return nullptr;
    }

  public:
    FooterParserAndroid(std::shared_ptr<IKeyCrypto> key_crypto) : key_crypto_(std::move(key_crypto)){};

    static inline bool IsUnsupportedAndroidSTag(const uint8_t *magic_u32)
    {
        static constexpr std::array<uint8_t, 4> kMagic = {'S', 'T', 'a', 'g'};
        return std::equal(kMagic.begin(), kMagic.end(), magic_u32);
    }

    static inline bool IsAndroidQTag(const uint8_t *magic_u32)
    {
        static constexpr std::array<uint8_t, 4> kMagic = {'Q', 'T', 'a', 'g'};
        return std::equal(kMagic.begin(), kMagic.end(), magic_u32);
    }

    std::unique_ptr<FooterParseResult> Parse(const uint8_t *file_footer, size_t len)
    {
        constexpr size_t kMinRequiredLen = 8;

        if (len < kMinRequiredLen)
        {
            return std::make_unique<FooterParseResult>(FooterParseState::NeedMoreBytes, kMinRequiredLen);
        }

        const auto *footer_payload_end = &file_footer[len - sizeof(uint32_t) - sizeof(uint32_t)];
        size_t footer_len = ReadBigEndian<uint32_t>(footer_payload_end) + sizeof(uint32_t) + sizeof(uint32_t);
        if (len < footer_len)
        {
            return std::make_unique<FooterParseResult>(FooterParseState::NeedMoreBytes, footer_len);
        }

        const auto *key_begin = &file_footer[len - footer_len];
        const auto *key_end = FindComma(key_begin, footer_payload_end);
        if (key_end == nullptr)
        {
            return std::make_unique<FooterParseResult>(FooterParseState::KeyDecryptionFailure, footer_len);
        }

        auto key = key_crypto_->Decrypt(key_begin, std::distance(key_begin, key_end));
        if (key.empty())
        {
            return std::make_unique<FooterParseResult>(FooterParseState::KeyDecryptionFailure, footer_len);
        }

        return std::make_unique<FooterParseResult>(FooterParseState::OK, footer_len, key);
    }
};

} // namespace parakeet_crypto::qmc2
