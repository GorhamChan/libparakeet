#include "parakeet-crypto/misc/QMCKeyDeriver.h"
#include "utils/base64.h"

#include "tc_tea/tc_tea.h"

#include <algorithm>
#include <iterator>

#include <cassert>
#include <cmath>

namespace parakeet_crypto::misc::tencent {

namespace detail {
const static std::array<char, 18> kEncV2Prefix = {'Q', 'Q', 'M', 'u', 's', 'i', 'c', ' ', 'E',
                                                  'n', 'c', 'V', '2', ',', 'K', 'e', 'y', ':'};
constexpr std::size_t kEncV2PrefixSize = kEncV2Prefix.size();

class QMCKeyDeriverImpl : public QMCKeyDeriver {
 public:
  QMCKeyDeriverImpl(uint8_t seed, QMCEncV2Stage1Key enc_v2_stage1_key, QMCEncV2Stage2Key enc_v2_stage2_key)
      : seed_(seed), enc_v2_stage1_key_(enc_v2_stage1_key), enc_v2_stage2_key_(enc_v2_stage2_key) {}

  bool FromEKey(std::vector<uint8_t>& out, const std::string& ekey_b64) const override {
    std::vector<uint8_t> ekey = utils::Base64Decode(ekey_b64);
    return FromEKey(out, ekey);
  }

  bool FromEKey(std::vector<uint8_t>& out, std::span<const uint8_t> ekey) const override {
    out.resize(0);

    if (std::equal(kEncV2Prefix.begin(), kEncV2Prefix.end(), ekey.begin())) {
      auto encryptedKeyBody = std::span{ekey.begin() + kEncV2PrefixSize, ekey.size() - kEncV2PrefixSize};
      auto v2KeyDecrypted = DecryptEncV2Key(encryptedKeyBody);
      if (v2KeyDecrypted.empty()) {
        return false;
      }
      return FromEKey(out, v2KeyDecrypted);
    }

    const auto ekey_len = ekey.size();
    if (ekey_len < 8) {
      return false;
    }

    auto tea_key = DeriveTEAKey(ekey);
    auto key = tc_tea::CBC_Decrypt(std::span{&ekey[8], ekey_len - 8}, tea_key);
    if (key.empty()) {
      return false;
    }

    std::merge(ekey.begin(), ekey.begin() + 8, key.begin(), key.end(), std::back_inserter(out));
    return true;
  }

  bool ToEKey(std::vector<uint8_t>& ekey, const std::span<const uint8_t> key) const override {
    ekey.resize(0);
    auto tea_key = DeriveTEAKey(key);

    if (auto cipher = tc_tea::CBC_Encrypt(std::span{&key[8], key.size() - 8}, tea_key); !cipher.empty()) {
      std::merge(key.begin(), key.begin() + 8, cipher.begin(), cipher.end(), std::back_inserter(ekey));
      return true;
    }

    return false;
  }

 private:
  uint8_t seed_;
  QMCEncV2Stage1Key enc_v2_stage1_key_;
  QMCEncV2Stage2Key enc_v2_stage2_key_;

  inline void MakeSimpleKey(std::span<uint8_t> out) const {
    auto seed = static_cast<double>(seed_);
    for (auto& byte : out) {
      byte = static_cast<uint8_t>(fabs(tan(seed)) * 100.0);
      seed += 0.1;
    }
  }

  inline auto DeriveTEAKey(std::span<const uint8_t> ekey) const -> std::array<uint8_t, 16> {
    assert(ekey.size() >= 8);

    std::array<uint8_t, 16> tea_key = {};
    std::array<uint8_t, 8> simple_key = {};
    MakeSimpleKey(simple_key);

    for (int i = 0; i < 16; i += 2) {
      tea_key[i + 0] = simple_key[i / 2];
      tea_key[i + 1] = ekey[i / 2];
    }

    return tea_key;
  }

  inline std::vector<uint8_t> DecryptEncV2Key(std::span<const uint8_t> cipher) const {
    auto stage1 = tc_tea::CBC_Decrypt(cipher, enc_v2_stage1_key_);
    auto stage2 = tc_tea::CBC_Decrypt(stage1, enc_v2_stage2_key_);

    if (stage1.empty() || stage2.empty()) {
      return {};
    }

    return utils::Base64Decode(stage2);
  }
};

}  // namespace detail

std::unique_ptr<QMCKeyDeriver> QMCKeyDeriver::Create(uint8_t seed,
                                                     QMCEncV2Stage1Key enc_v2_stage1_key,
                                                     QMCEncV2Stage2Key enc_v2_stage2_key) {
  return std::make_unique<detail::QMCKeyDeriverImpl>(seed, enc_v2_stage1_key, enc_v2_stage2_key);
}

}  // namespace parakeet_crypto::misc::tencent
