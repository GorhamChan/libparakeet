#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <array>
#include <memory>
#include <span>

namespace parakeet_crypto::decryptor {

namespace joox {

using JooxSalt = std::array<uint8_t, 16>;
using JooxSaltInput = std::span<const uint8_t, 16>;

}  // namespace joox

std::unique_ptr<StreamDecryptor> CreateJooxDecryptor(const std::string& install_uuid, joox::JooxSaltInput salt);

}  // namespace parakeet_crypto::decryptor
