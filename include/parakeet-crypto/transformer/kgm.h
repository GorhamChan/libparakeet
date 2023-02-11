#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

struct KGMConfigV4
{
    std::vector<uint8_t> slot_key_table;
    std::vector<uint8_t> file_key_table;
};

struct KGMConfig
{
    std::map<uint32_t, std::vector<uint8_t>> slot_keys{};
    KGMConfigV4 v4;
};

std::unique_ptr<ITransformer> CreateKGMDecryptionTransformer(KGMConfig config);

} // namespace parakeet_crypto::transformer
