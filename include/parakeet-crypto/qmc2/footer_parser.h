#pragma once

#include "key_crypto.h"

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

    virtual std::unique_ptr<FooterParseResult> ParseFooter(const uint8_t *file_footer, size_t len) = 0;
};

std::unique_ptr<QMCFooterParser> CreateQMC2FooterParser(std::shared_ptr<IKeyCrypto> key_crypto);

} // namespace parakeet_crypto::qmc2
