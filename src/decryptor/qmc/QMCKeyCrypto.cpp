#include "parakeet-crypto/decryptor/qmc/QMCKeyCrypto.h"
#include "utils/base64.h"

#include "tc_tea/tc_tea.h"

#include <algorithm>
#include <iterator>

#include <cassert>
#include <cmath>

namespace parakeet_crypto::qmc {

namespace tea_key {

inline void MakeSimpleKey(std::span<uint8_t> out) {
    constexpr double kInitialSeed = 106.0;
    constexpr double kMultiplier = 100.0;
    constexpr double kSeedDelta = 0.1;

    auto seed = kInitialSeed;
    for (auto& byte : out) {
        byte = static_cast<uint8_t>(fabs(tan(seed)) * kMultiplier);
        seed += kSeedDelta;
    }
}

constexpr std::size_t kTEAKeySize = 16;
inline std::array<uint8_t, kTEAKeySize> DeriveTEAKey(std::span<const uint8_t> ekey) {
    constexpr std::size_t kEkeySize = 8;

    assert(ekey.size() >= kEkeySize);

    std::array<uint8_t, kTEAKeySize> tea_key = {};
    std::array<uint8_t, kEkeySize> simple_key = {};
    MakeSimpleKey(simple_key);

    for (int i = 0; i < tea_key.size(); i += 2) {
        tea_key[i + 0] = simple_key[i / 2];
        tea_key[i + 1] = ekey[i / 2];
    }

    return tea_key;
}

}  // namespace tea_key

namespace detail {
const static std::array<char, 18> kEncV2Prefix = {'Q', 'Q', 'M', 'u', 's', 'i', 'c', ' ', 'E',
                                                  'n', 'c', 'V', '2', ',', 'K', 'e', 'y', ':'};

class KeyCryptoImpl : public KeyCrypto {
   private:
    EncV2Stage1Key enc_v2_stage1_key_{};
    EncV2Stage2Key enc_v2_stage2_key_{};

   public:
    KeyCryptoImpl(EncV2Stage1KeyInput enc_v2_stage1_key, EncV2Stage2KeyInput enc_v2_stage2_key) {
        // Size must match!
        assert(enc_v2_stage1_key.size() == enc_v2_stage1_key_.size());
        assert(enc_v2_stage2_key.size() == enc_v2_stage2_key_.size());

        std::ranges::copy(enc_v2_stage1_key, enc_v2_stage1_key_.begin());
        std::ranges::copy(enc_v2_stage2_key, enc_v2_stage2_key_.begin());
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> Decrypt(const std::string& ekey_b64) const override {
        std::vector<uint8_t> ekey = utils::Base64Decode(ekey_b64);
        return Decrypt(ekey);
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> Decrypt(std::span<const uint8_t> ekey) const override {
        std::vector<uint8_t> v2KeyDecrypted{};
        constexpr std::size_t kUnscrambledFirstPartSize = 8;

        if (ekey.size() >= kEncV2Prefix.size() && std::equal(kEncV2Prefix.begin(), kEncV2Prefix.end(), ekey.begin())) {
            v2KeyDecrypted = DecryptEncV2Key(ekey.subspan(kEncV2Prefix.size()));
            // Decrypt failed?
            if (v2KeyDecrypted.empty()) {
                return {};
            }
            ekey = std::span{v2KeyDecrypted};
        }

        if (ekey.size() < kUnscrambledFirstPartSize) {
            return {};
        }

        auto tea_key = tea_key::DeriveTEAKey(ekey);
        auto decrypted_key = tc_tea::CBC_Decrypt(ekey.subspan(kUnscrambledFirstPartSize), tea_key);
        if (decrypted_key.empty()) {
            return {};
        }

        std::vector<uint8_t> final_key;
        final_key.reserve(kUnscrambledFirstPartSize + decrypted_key.size());
        final_key.insert(final_key.end(), ekey.begin(), ekey.begin() + kUnscrambledFirstPartSize);
        final_key.insert(final_key.end(), decrypted_key.begin(), decrypted_key.end());
        return final_key;
    }

    [[nodiscard]] inline std::vector<uint8_t> DecryptEncV2Key(std::span<const uint8_t> cipher) const {
        auto stage1 = tc_tea::CBC_Decrypt(cipher, enc_v2_stage1_key_);
        if (stage1.empty()) {
            return {};
        }

        auto stage2 = tc_tea::CBC_Decrypt(stage1, enc_v2_stage2_key_);
        if (stage2.empty()) {
            return {};
        }

        return utils::Base64Decode(stage2);
    }
};

}  // namespace detail

std::unique_ptr<KeyCrypto> CreateKeyCrypto(EncV2Stage1KeyInput enc_v2_stage1_key,
                                           EncV2Stage2KeyInput enc_v2_stage2_key) {
    return std::make_unique<detail::KeyCryptoImpl>(enc_v2_stage1_key, enc_v2_stage2_key);
}

}  // namespace parakeet_crypto::qmc
