#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

namespace parakeet_crypto::decryptor {

using JooxSalt = std::array<uint8_t, 16>;

std::unique_ptr<StreamDecryptor> CreateJooxDecryptor(const std::string& install_uuid, std::span<const uint8_t> salt);

}  // namespace parakeet_crypto::decryptor
