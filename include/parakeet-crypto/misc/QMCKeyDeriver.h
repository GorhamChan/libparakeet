#pragma once

#include <array>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <cstdint>

namespace parakeet_crypto::misc::tencent {
using QMCEncV2Stage1Key = std::array<uint8_t, 16>;
using QMCEncV2Stage2Key = std::array<uint8_t, 16>;

class QMCKeyDeriver {
 public:
  virtual ~QMCKeyDeriver() = default;
  virtual bool FromEKey(std::vector<uint8_t>& file_key, const std::string& ekey_b64) const = 0;
  virtual bool FromEKey(std::vector<uint8_t>& file_key, std::span<const uint8_t> ekey) const = 0;
  virtual bool ToEKey(std::vector<uint8_t>& ekey, std::span<const uint8_t> file_key) const = 0;

  static std::unique_ptr<QMCKeyDeriver> Create(uint8_t seed,
                                               QMCEncV2Stage1Key enc_v2_stage1_key,
                                               QMCEncV2Stage2Key enc_v2_stage2_key);
};

}  // namespace parakeet_crypto::misc::tencent
