#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace parakeet_crypto::transformer
{

constexpr size_t kJooxSaltLen{16};

struct JooxConfig
{
    std::string install_uuid;
    std::array<uint8_t, kJooxSaltLen> salt;
};

std::unique_ptr<ITransformer> CreateJooxDecryptionV4Transformer(JooxConfig config);
std::unique_ptr<ITransformer> CreateJooxEncryptionV4Transformer(JooxConfig config);

} // namespace parakeet_crypto::transformer
