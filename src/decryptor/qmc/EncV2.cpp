#include "EncV2.h"

#include "utils/base64.h"

#include <tc_tea/tc_tea.h>

namespace parakeet_crypto::qmc::tea_key {

// NOLINTBEGIN(*-magic-numbers, bugprone-easily-swappable-parameters)

[[nodiscard]] std::vector<uint8_t> DecryptEncV2Key(std::span<const uint8_t> cipher,
                                                   EncV2StageKeyInput stage_1_key,
                                                   EncV2StageKeyInput stage_2_key) {
    if (auto stage1 = tc_tea::CBC_Decrypt(cipher, stage_1_key); !stage1.empty()) {
        if (auto stage2 = tc_tea::CBC_Decrypt(stage1, stage_2_key); !stage2.empty()) {
            return utils::Base64Decode(stage2);
        }
    }

    return {};
}

[[nodiscard]] std::vector<uint8_t> EncryptEncV2Key(std::span<const uint8_t> plain,
                                                   EncV2StageKeyInput stage_1_key,
                                                   EncV2StageKeyInput stage_2_key) {
    auto stage2_encoded = utils::Base64EncodeBytes(plain);
    auto stage2 = tc_tea::CBC_Encrypt(stage2_encoded, stage_2_key);
    auto stage1 = tc_tea::CBC_Encrypt(stage2, stage_1_key);
    return stage1;
}

// NOLINTEND(*-magic-numbers, bugprone-easily-swappable-parameters)

}  // namespace parakeet_crypto::qmc::tea_key
