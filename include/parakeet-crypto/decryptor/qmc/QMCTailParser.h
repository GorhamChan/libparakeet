#pragma once

#include "QMCKeyCrypto.h"

#include <cstdint>

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace parakeet_crypto::qmc
{

class TailParser
{
  public:
    using ParsedTailResult = std::pair<std::size_t, std::vector<uint8_t>>;

    virtual ~TailParser() = default;

    /**
     * @brief Parse a given block of footer data (suggested: 1024 bytes).
     *
     * @param data Tail pointer
     * @return std::optional<ParsedTailResult>
     */
    [[nodiscard]] virtual std::optional<ParsedTailResult> Parse(std::span<const uint8_t> data) const = 0;
};

std::unique_ptr<TailParser> CreateTailParser(const std::shared_ptr<KeyCrypto> &key_crypto);

} // namespace parakeet_crypto::qmc
