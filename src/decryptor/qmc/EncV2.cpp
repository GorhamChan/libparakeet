#include "EncV2.h"

#include "utils/base64.h"

#include <tc_tea/tc_tea.h>

namespace parakeet_crypto::qmc::tea_key {

// NOLINTBEGIN(*-magic-numbers, bugprone-easily-swappable-parameters)

[[nodiscard]] std::vector<uint8_t> DecryptEncV2Key(const uint8_t* cipher,
                                                   size_t cipher_len,
                                                   const uint8_t* stage_1_key,
                                                   const uint8_t* stage_2_key) {
    std::vector<uint8_t> plain(cipher_len);
    size_t plain_len = cipher_len;
    if (tc_tea::CBC_Decrypt(plain.data(), &plain_len, cipher, cipher_len, stage_1_key)) {
        if (tc_tea::CBC_Decrypt(plain.data(), &plain_len, plain.data(), plain_len, stage_2_key)) {
            plain.resize(plain_len);
            return utils::Base64Decode(plain);
        }
    }

    return {};
}

[[nodiscard]] std::vector<uint8_t> EncryptEncV2Key(const uint8_t* plain,
                                                   size_t plain_len,
                                                   const uint8_t* stage_1_key,
                                                   const uint8_t* stage_2_key) {
    auto ekey_b64 = utils::Base64Encode(plain, plain_len);
    auto stage2 = tc_tea::CBC_Encrypt(ekey_b64, stage_2_key);
    auto stage1 = tc_tea::CBC_Encrypt(stage2, stage_1_key);
    return stage1;
}

// NOLINTEND(*-magic-numbers, bugprone-easily-swappable-parameters)

}  // namespace parakeet_crypto::qmc::tea_key
