#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"

#include <map>

namespace parakeet_crypto::decryption::kugou {

typedef std::vector<uint8_t> KugouSingleSlotKey;
typedef std::map<uint32_t, KugouSingleSlotKey> KugouSlotKeys;
typedef std::vector<uint8_t> KugouV4SlotKeyExpansionTable;
typedef std::vector<uint8_t> KugouV4FileKeyExpansionTable;

class KugouFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "Kugou"; };

  /**
   * @brief Create KugouFileLoader for KGM / VPR.
   */
  static std::unique_ptr<KugouFileLoader> Create(const KugouSlotKeys& slot_keys,
                                                 const KugouV4SlotKeyExpansionTable& v4_slot_key_expansion_table,
                                                 const KugouV4FileKeyExpansionTable& v4_file_key_expansion_table);
};

}  // namespace parakeet_crypto::decryption::kugou
