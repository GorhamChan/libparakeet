#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <map>
#include <memory>
#include <span>
#include <vector>

namespace parakeet_crypto::decryptor {

using KugouSingleSlotKey = std::vector<uint8_t>;
using KugouSlotKeys = std::map<uint32_t, KugouSingleSlotKey>;
using KugouV4SlotKeyExpansionTable = std::vector<uint8_t>;
using KugouV4FileKeyExpansionTable = std::vector<uint8_t>;

/**
 * @brief Create KugouFileLoader for KGM / VPR.
 */
std::unique_ptr<StreamDecryptor> CreateKugouDecryptor(const KugouSlotKeys& slot_keys,
                                                      std::span<const uint8_t> v4_slot_key_expansion_table,
                                                      std::span<const uint8_t> v4_file_key_expansion_table);
}  // namespace parakeet_crypto::decryptor
