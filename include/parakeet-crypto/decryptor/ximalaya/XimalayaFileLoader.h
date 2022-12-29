#pragma once

#include "parakeet-crypto/decryptor/DecryptionStream.h"

#include <array>
#include <span>

namespace parakeet_crypto::decryption::ximalaya {

constexpr std::size_t kX2MContentKeySize = 0x04;
constexpr std::size_t kX3MContentKeySize = 0x20;
constexpr std::size_t kScrambleTableSize = 0x400;

typedef std::array<uint8_t, kX2MContentKeySize> X2MContentKey;
typedef std::array<uint8_t, kX3MContentKeySize> X3MContentKey;
typedef std::array<uint16_t, kScrambleTableSize> ScrambleTable;

struct XmlyScrambleTableParameter {
  double init_value = 0;
  double step_value = 0;
};

class XimalayaFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "Ximalaya"; };

  static std::unique_ptr<XimalayaFileLoader> Create(const X2MContentKey& key, const ScrambleTable& scramble_table);
  static std::unique_ptr<XimalayaFileLoader> Create(const X3MContentKey& key, const ScrambleTable& scramble_table);

  /**
   * @brief Create a Ximalaya X2M / X3M decryptor.
   *
   * @param key Content key, which can have a size of 4 or 32.
   * @param table_parameters Parameters used to generate this table, with `init_value` and `step_value`.
   * @return std::unique_ptr<XimalayaFileLoader>
   */
  static std::unique_ptr<XimalayaFileLoader> Create(const std::span<const uint8_t>& key,
                                                    const XmlyScrambleTableParameter& table_parameters);
};

}  // namespace parakeet_crypto::decryption::ximalaya
