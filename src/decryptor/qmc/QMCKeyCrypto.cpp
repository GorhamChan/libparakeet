#include "parakeet-crypto/decryptor/qmc/QMCKeyCrypto.h"
#include "EncV2.h"

#include "TEAKeyDerive.h"
#include "utils/base64.h"

#include <tc_tea/tc_tea.h>

#include <algorithm>
#include <iterator>

#include <cassert>
#include <cmath>

namespace parakeet_crypto::qmc {

namespace detail {
const static std::array<char, 18> kEncV2Prefix = {'Q', 'Q', 'M', 'u', 's', 'i', 'c', ' ', 'E',
                                                  'n', 'c', 'V', '2', ',', 'K', 'e', 'y', ':'};

class KeyCryptoImpl : public KeyCrypto {
   private:
    EncV2Stage1Key enc_v2_stage1_key_{};
    EncV2Stage2Key enc_v2_stage2_key_{};
    static constexpr std::size_t kPlaintextKeyPrefixLen = 8;

   public:
    KeyCryptoImpl(EncV2Stage1KeyInput enc_v2_stage1_key, EncV2Stage2KeyInput enc_v2_stage2_key) {
        // Size must match!
        assert(enc_v2_stage1_key.size() == enc_v2_stage1_key_.size());
        assert(enc_v2_stage2_key.size() == enc_v2_stage2_key_.size());

        std::copy(enc_v2_stage1_key.begin(), enc_v2_stage1_key.end(), enc_v2_stage1_key_.begin());
        std::copy(enc_v2_stage2_key.begin(), enc_v2_stage2_key.end(), enc_v2_stage2_key_.begin());
    }

    [[nodiscard]] static std::optional<std::vector<uint8_t>> DecryptV1Key(const uint8_t* ekey, size_t ekey_len) {
        if (ekey_len < kPlaintextKeyPrefixLen) {
            return {};
        }

        std::array<uint8_t, tea_key::kSize> decryption_key{};
        tea_key::DeriveTEAKey(decryption_key.begin(), decryption_key.end(), ekey);

        std::vector<uint8_t> final_key(ekey_len);
        size_t final_key_len = ekey_len - kPlaintextKeyPrefixLen;
        if (!tc_tea::CBC_Decrypt(&final_key[kPlaintextKeyPrefixLen], &final_key_len,  //
                                 &ekey[kPlaintextKeyPrefixLen], final_key_len,        //
                                 decryption_key.data())) {
            return {};
        }
        final_key.resize(kPlaintextKeyPrefixLen + final_key_len);
        return final_key;
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> Decrypt(const std::string& ekey_b64) const override {
        std::vector<uint8_t> ekey = utils::Base64Decode(ekey_b64);
        return Decrypt(ekey.data(), ekey.size());
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> Decrypt(const uint8_t* ekey, size_t ekey_len) const override {
        if (ekey_len >= kEncV2Prefix.size() && std::equal(kEncV2Prefix.begin(), kEncV2Prefix.end(), ekey)) {
            auto decoded_ekey =
                tea_key::DecryptEncV2Key(ekey, ekey_len, enc_v2_stage1_key_.data(), enc_v2_stage2_key_.data());
            if (decoded_ekey.empty()) {
                return {};  // failed to decrypt EncV2 key
            }

            return DecryptV1Key(decoded_ekey.data(), decoded_ekey.size());
        }

        return DecryptV1Key(ekey, ekey_len);
    }
};

}  // namespace detail

std::unique_ptr<KeyCrypto> CreateKeyCrypto(EncV2Stage1KeyInput enc_v2_stage1_key,
                                           EncV2Stage2KeyInput enc_v2_stage2_key) {
    return std::make_unique<detail::KeyCryptoImpl>(enc_v2_stage1_key, enc_v2_stage2_key);
}

}  // namespace parakeet_crypto::qmc
