#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <array>
#include <memory>
#include <string>

#include <cstdint>

namespace parakeet_crypto::decryptor {

namespace netease {

// AES Key; which can be used to decrypt the embedded "content key"
constexpr std::size_t kNCMContentKeyProtectionKeySize = 128 / 8;
using NCMContentKeyProtectionKey = std::array<uint8_t, kNCMContentKeyProtectionKeySize>;
using NCMContentKeyProtectionKeyInput = std::span<const uint8_t, netease::kNCMContentKeyProtectionKeySize>;

}  // namespace netease

std::unique_ptr<StreamDecryptor> CreateNeteaseDecryptor(netease::NCMContentKeyProtectionKeyInput key);

}  // namespace parakeet_crypto::decryptor
