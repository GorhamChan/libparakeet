#pragma once

#include <array>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <cstdint>

namespace parakeet_crypto::qmc {

using EncV2Stage1Key = std::array<uint8_t, 16>;
using EncV2Stage1KeyInput = std::span<const uint8_t, 16>;

using EncV2Stage2Key = std::array<uint8_t, 16>;
using EncV2Stage2KeyInput = std::span<const uint8_t, 16>;

// FIXME: Not tested

class KeyCrypto {
   public:
    virtual ~KeyCrypto() = default;

    virtual std::optional<std::vector<uint8_t>> Decrypt(const std::string& ekey_b64) const = 0;
    virtual std::optional<std::vector<uint8_t>> Decrypt(std::span<const uint8_t> ekey) const = 0;
};

std::unique_ptr<KeyCrypto> CreateKeyCrypto(EncV2Stage1KeyInput enc_v2_stage1_key,
                                           EncV2Stage2KeyInput enc_v2_stage2_key);

}  // namespace parakeet_crypto::qmc
