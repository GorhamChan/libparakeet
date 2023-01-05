#include "parakeet-crypto/decryptor/qmc/QMCKeyCrypto.h"

#include "EncV2.h"
#include "utils/base64.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <numeric>
#include <vector>

using ::testing::ElementsAreArray;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers)

const std::string kEncryptedKeyV1 =
    "OWJ3WFZGSHXtNC0sRA/5GBYejC8ja4fIK7DI02ML04NJBQVgTTymzRxM//VbFCDqjv22iGYivHMd0Y+WQADQ+W7KtRrn70+7W9UJa6mIR6YOx2"
    "f0EVjhc61+Mfrsf+adgqs631UBxpPrYg2StP+1OyTAgtUtSPkf2V3CS4+SE60dbqdBuhgkUSBjqBkC1gniljcA2mC6krzWgg1DBtqfA1ZSAR73"
    "NB/g3DpT3u5IDR5i7Zq7Rc9UNicydVjFd696ELZMaMjuNo1MXrsrRClIu71Kp+fWmS7nZOHrakQK00UdaxnlbGbWYRKmdS0bEq+QnlfcP3yAMi"
    "WTQjyRYRUbhlBP8POyLQQUQaTFNBw7HPU=";

const auto kExpectedKey = std::to_array<uint8_t>({
    '9', 'b', 'w', 'X', 'V', 'F', 'H', 'u', 'o', 'I', '4', '1', 'E', 'S', 'I', '9', 'Z', '8', 'W', 'h', 'u', 'Q',
    'u', 't', 'U', 'M', '8', '5', 'X', 'n', 'P', 'v', '1', 'r', '8', '1', 'p', 'y', '4', 't', '4', '2', 't', '0',
    '1', '4', '8', 'E', 'u', '5', 'x', 'Q', '8', 'a', 'J', '5', 'D', '9', '9', 'r', 'S', 'O', 'n', 'l', '3', 'D',
    'N', '5', '3', 'H', 'Y', '1', '2', 'c', '1', 'O', 'k', '4', 'W', 'H', 'O', '6', 'h', '0', 'H', '8', 'S', 'J',
    'n', 'd', 'E', '3', '0', 'M', 'z', 'K', '3', 'o', 'Q', 'k', 'y', '5', 'R', 'm', 'B', '6', 'n', 'V', '9', '3',
    '4', 'Q', 'G', 'd', 'L', 'v', '7', '3', 'Q', '6', 'l', '8', '3', '6', 'E', '8', 'n', '1', '5', 'R', '5', '6',
    'N', 'M', 'r', 'X', '0', 'D', 'P', 'y', 'h', 'h', 'r', '1', 'K', 'd', 's', 'L', 'C', 'N', 'V', 'Y', 'H', '9',
    'q', 'U', '0', 'T', '6', '7', 'q', 'A', '5', 'U', '5', 'M', 'V', '6', '7', 'E', '7', 'F', '4', 'S', '1', '2',
    'q', 'R', 'c', 'y', '3', '1', 'Z', 'X', 'J', 'X', '8', '3', '1', 'x', 'a', 'b', 'y', 'a', '5', 's', '2', 'v',
    '5', 'g', '0', 'c', 'K', 'k', '2', 'o', 'T', 'z', '7', '4', 'F', '5', '6', 'm', '5', 'P', '8', 'j', 'Y', 'E',
    '1', 'k', 'M', '2', 'Q', '0', 'Z', 's', '4', '4', 'Z', 'G', '6', 'I', 'l', 'K', 'j', 'R', 'I', '0', 'w', 'v',
    '1', 'C', '0', 'D', 't', 'T', '1', 'h', 'u', 'g', '8', '8', '8', 'z',
});

TEST(KeyCrypto, DecryptBasicKeyDecryption) {
    qmc::EncV2Stage1Key stage1_key{};
    qmc::EncV2Stage1Key stage2_key{};
    std::iota(stage1_key.begin(), stage1_key.end(), 0x66);
    std::iota(stage2_key.begin(), stage2_key.end(), 0x99);

    auto qmc_key_crypto = qmc::CreateKeyCrypto(stage1_key, stage2_key);
    auto key = qmc_key_crypto->Decrypt(kEncryptedKeyV1);
    assert(key.has_value());
    ASSERT_THAT(*key, ElementsAreArray(kExpectedKey));
}

TEST(KeyCrypto, DecryptEncV2Key) {
    qmc::EncV2Stage1Key stage1_key{};
    qmc::EncV2Stage1Key stage2_key{};
    std::iota(stage1_key.begin(), stage1_key.end(), 0x66);
    std::iota(stage2_key.begin(), stage2_key.end(), 0x99);

    const static std::array<char, 18> kEncV2Prefix = {'Q', 'Q', 'M', 'u', 's', 'i', 'c', ' ', 'E',
                                                      'n', 'c', 'V', '2', ',', 'K', 'e', 'y', ':'};

    auto key_enc_v1 = utils::Base64Decode(kEncryptedKeyV1);
    auto key_enc_v2 = qmc::tea_key::EncryptEncV2Key(key_enc_v1, stage1_key, stage2_key);
    key_enc_v2.insert(key_enc_v2.begin(), kEncV2Prefix.cbegin(), kEncV2Prefix.cend());
    auto key_enc_v2_b64 = utils::Base64Encode(key_enc_v2);

    auto qmc_key_crypto = qmc::CreateKeyCrypto(stage1_key, stage2_key);
    auto key = qmc_key_crypto->Decrypt(key_enc_v2_b64);
    ASSERT_TRUE(key.has_value());
    if (key) {
        ASSERT_THAT(*key, ElementsAreArray(kExpectedKey));
    }
}

// NOLINTEND(*-magic-numbers)
