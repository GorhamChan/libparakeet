#include "parakeet-crypto/qmc2/key_crypto.h"

#include <array>
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

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

#pragma region fixture
constexpr const std::array<uint8_t, 256> kExpectedKey = {
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
};
#pragma endregion

TEST(QMCKeyCrypto, EncV1)
{
    std::array<uint8_t, 16> key_1{};
    std::array<uint8_t, 16> key_2{};
    std::iota(key_1.begin(), key_1.end(), 0x66);
    std::iota(key_2.begin(), key_2.end(), 0x99);

    auto key_crypto = qmc2::CreateKeyCrypto(123, key_1.data(), key_2.data());
    auto key_enc_v1 = key_crypto->Encrypt(kExpectedKey.data(), kExpectedKey.size(), qmc2::KeyVersion::VERSION_1);
    ASSERT_EQ(key_enc_v1.size(), 364);
    auto key = key_crypto->Decrypt(key_enc_v1.data(), key_enc_v1.size());
    ASSERT_THAT(key, ElementsAreArray(kExpectedKey));
}

TEST(QMCKeyCrypto, EncV2)
{
    std::array<uint8_t, 16> key_1{};
    std::array<uint8_t, 16> key_2{};
    std::iota(key_1.begin(), key_1.end(), 0x66);
    std::iota(key_2.begin(), key_2.end(), 0x99);

    auto key_crypto = qmc2::CreateKeyCrypto(123, key_1.data(), key_2.data());
    auto key_enc_v2 = key_crypto->Encrypt(kExpectedKey.data(), kExpectedKey.size(), qmc2::KeyVersion::VERSION_2);
    ASSERT_EQ(key_enc_v2.size(), 548);
    auto key = key_crypto->Decrypt(key_enc_v2.data(), key_enc_v2.size());
    ASSERT_THAT(key, ElementsAreArray(kExpectedKey));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
