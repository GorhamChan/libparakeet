#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <memory>

namespace parakeet_crypto::decryptor
{

std::unique_ptr<StreamDecryptor> CreateXiamiDecryptor();

} // namespace parakeet_crypto::decryptor
