#pragma once

#include "parakeet-crypto/qmc2/footer_parser.h"
#include "parakeet-crypto/qmc2/key_crypto.h"
#include "utils/EndianHelper.h"

#include <cstdint>
#include <iterator>
#include <memory>
#include <utility>

namespace parakeet_crypto::qmc2
{

// Legacy PC QQMusic encoded format.
// ekey_b64 := [ansi ekey_b64]
// eof_mark := [(le)uint32_t ekey_size]
// qmc_file := [encrypted_data] [ekey_b64] [eof_mark]
class FooterParserPC
{
    std::shared_ptr<IKeyCrypto> key_crypto_;

  public:
    FooterParserPC(std::shared_ptr<IKeyCrypto> key_crypto) : key_crypto_(std::move(key_crypto)){};

    static inline bool IsPCFooter(const uint8_t *magic_u32)
    {
        constexpr uint32_t kMaxPCKeyLen = 0x500;
        return ReadLittleEndian<uint32_t>(magic_u32) < kMaxPCKeyLen;
    }

    std::unique_ptr<FooterParseResult> Parse(const uint8_t *file_footer, size_t len)
    {
        const auto *footer_payload_end = &file_footer[len - sizeof(uint32_t)];
        size_t footer_len = ReadLittleEndian<uint32_t>(footer_payload_end) + sizeof(uint32_t);
        if (footer_len > len)
        {
            return std::make_unique<FooterParseResult>(FooterParseState::NeedMoreBytes, footer_len);
        }

        const auto *footer_begin = &file_footer[len - footer_len];
        auto key = key_crypto_->Decrypt(footer_begin, std::distance(footer_begin, footer_payload_end));
        if (key.empty())
        {
            return std::make_unique<FooterParseResult>(FooterParseState::KeyDecryptionFailure, footer_len);
        }

        return std::make_unique<FooterParseResult>(FooterParseState::OK, footer_len, key);
    }
};

} // namespace parakeet_crypto::qmc2
