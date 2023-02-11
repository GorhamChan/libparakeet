#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <memory>

namespace parakeet_crypto::transformer
{

std::unique_ptr<ITransformer> CreateXiamiDecryptionTransformer();

} // namespace parakeet_crypto::transformer
