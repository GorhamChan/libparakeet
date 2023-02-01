#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <map>
#include <memory>
#include <span>
#include <vector>

namespace parakeet_crypto::decryptor
{

namespace kugou
{

using KugouSingleSlotKey = std::vector<uint8_t>;
using KugouSlotKeys = std::map<uint32_t, KugouSingleSlotKey>;

using KugouV4SlotKeyExpansionTable = std::vector<uint8_t>;
using KugouV4FileKeyExpansionTable = std::vector<uint8_t>;

using KugouV4SlotKeyExpansionTableInput = std::span<const uint8_t>;
using KugouV4FileKeyExpansionTableInput = std::span<const uint8_t>;

} // namespace kugou

/**
 * @brief Create KugouFileLoader for KGM / VPR.
 */
std::unique_ptr<StreamDecryptor> CreateKugouDecryptor(
    const kugou::KugouSlotKeys &slot_keys, kugou::KugouV4SlotKeyExpansionTableInput v4_slot_key_expansion_table,
    kugou::KugouV4FileKeyExpansionTableInput v4_file_key_expansion_table);
} // namespace parakeet_crypto::decryptor
