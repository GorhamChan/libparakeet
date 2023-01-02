#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <memory>
#include <span>

namespace parakeet_crypto::decryptor {

constexpr std::size_t kKuwoDecryptionKeySize = 0x20;
using KuwoKey = std::array<uint8_t, kKuwoDecryptionKeySize>;

std::unique_ptr<StreamDecryptor> CreateKuwoDecryptor(std::span<const uint8_t, kKuwoDecryptionKeySize> key);

}  // namespace parakeet_crypto::decryptor
