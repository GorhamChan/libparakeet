#pragma once

#include "key_crypto.h"
#include "parakeet-crypto/IStream.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace parakeet_crypto::qmc2
{

enum class FooterParseState
{
    OK = 0,
    NeedMoreBytes = 1,
    KeyDecryptionFailure = 2,
    UnsupportedAndroidClientSTag = 3,
    IOReadFailure = 4,
    UnknownContent = 9,
};

// NOLINTBEGIN(*-non-private-member-variables-in-classes)

struct FooterParseResult
{
    FooterParseState state{FooterParseState::UnknownContent};

    /**
     * @brief Footer size, does not contain any audio data.
     * When decrypting, ignore the last `footer_size` amount of bytes.
     */
    size_t footer_size{};

    /**
     * @brief ekey - decrypted
     */
    std::vector<uint8_t> key{};

    FooterParseResult(FooterParseState state, size_t footer_size, std::vector<uint8_t> key)
        : state(state), footer_size(footer_size), key(std::move(key))
    {
    }
    FooterParseResult(FooterParseState state, size_t footer_size) : state(state), footer_size(footer_size)
    {
    }
    FooterParseResult(FooterParseState state) : state(state)
    {
    }
};

// NOLINTEND(*-non-private-member-variables-in-classes)

class QMCFooterParser
{
  public:
    virtual ~QMCFooterParser() = default;

    virtual std::unique_ptr<FooterParseResult> Parse(const uint8_t *file_footer, size_t len) = 0;

    inline std::unique_ptr<FooterParseResult> Parse(IReadSeekable &input_stream)
    {
        constexpr size_t kInitialFooterSize = 1024;
        auto initial_seek_pos = input_stream.GetOffset();

        input_stream.Seek(-kInitialFooterSize, SeekDirection::FILE_END_BACKWARDS);
        std::vector<uint8_t> footer_buffer(kInitialFooterSize, 0);

        // In case of partial read (file too small?), keep track of the numuber of bytes available.
        auto bytes_read = input_stream.Read(footer_buffer.data(), footer_buffer.size());

        // 1st attempt to parse it
        auto footer = Parse(footer_buffer.data(), bytes_read);
        if (footer->state == qmc2::FooterParseState::NeedMoreBytes)
        {
            // We need more data, resize our buffer.
            footer_buffer.resize(footer->footer_size);
            input_stream.Seek(-footer->footer_size, SeekDirection::FILE_END_BACKWARDS);
            if (!input_stream.ReadExact(footer_buffer.data(), footer_buffer.size()))
            {
                input_stream.Seek(initial_seek_pos, SeekDirection::FILE_BEGIN);
                return std::make_unique<FooterParseResult>(FooterParseState::IOReadFailure, footer_buffer.size());
            }

            // 2nd attempt to parse it
            footer = Parse(footer_buffer.data(), footer->footer_size);
        }

        input_stream.Seek(initial_seek_pos, SeekDirection::FILE_BEGIN);
        return footer;
    }
};

std::unique_ptr<QMCFooterParser> CreateQMC2FooterParser(std::shared_ptr<IKeyCrypto> key_crypto);

inline std::unique_ptr<QMCFooterParser> CreateQMC2FooterParser(uint8_t seed, const uint8_t *enc_v2_key_1,
                                                               const uint8_t *enc_v2_key_2)
{
    return CreateQMC2FooterParser(CreateKeyCrypto(seed, enc_v2_key_1, enc_v2_key_2));
}

} // namespace parakeet_crypto::qmc2
