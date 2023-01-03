#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <cstdint>

#include <memory>
#include <span>

namespace parakeet_crypto::decryptor {

namespace tencent {

using QMCv2Key = std::span<uint8_t>;
using QMCv2KeyInput = std::span<const uint8_t>;

}  // namespace tencent

std::unique_ptr<StreamDecryptor> CreateQMCv2Decryptor(tencent::QMCv2KeyInput key);

}  // namespace parakeet_crypto::decryptor
