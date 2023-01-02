#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <array>
#include <memory>
#include <span>

#include <cstdint>

namespace parakeet_crypto::decryptor {

namespace kuwo {

constexpr std::size_t kKuwoDecryptionKeySize = 0x20;
using KuwoKey = std::array<uint8_t, kKuwoDecryptionKeySize>;
using KuwoKeyInput = std::span<const uint8_t, kKuwoDecryptionKeySize>;

}  // namespace kuwo

std::unique_ptr<StreamDecryptor> CreateKuwoDecryptor(kuwo::KuwoKeyInput key);

}  // namespace parakeet_crypto::decryptor
