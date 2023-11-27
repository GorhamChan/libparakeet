#include "parakeet-crypto/cipher/aes/aes.h"
#include "parakeet-crypto/cipher/block_mode/ctr.h"
#include "parakeet-crypto/cipher/cipher.h"
#include "parakeet-crypto/cipher/cipher_error.h"

#include "gmock/gmock.h"
#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <memory>
#include <vector>

using ::testing::ContainerEq;
using namespace parakeet_crypto::cipher;
using namespace parakeet_crypto::cipher::aes;
using namespace parakeet_crypto::cipher::block_mode;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

// NOLINTNEXTLINE
static uint8_t g_aes_128_ctr_test_key[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                        0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};

TEST(aes_128_ctr, simple_block_version)
{
    auto aes_enc = std::make_shared<AES128Enc>(&g_aes_128_ctr_test_key[0]);

    // NOLINTNEXTLINE
    uint8_t test_iv[] = {0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    const std::array<uint8_t, 17> input = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                           0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11};

    const std::vector<uint8_t> expected = {0x77, 0xB0, 0x8B, 0xB0, 0x94, 0x77, 0x62, 0xB8, 0x05,
                                           0xE7, 0xFF, 0x83, 0x9E, 0xE5, 0x6B, 0x9B, 0x00};

    // Update the whole thing
    {
        auto aes_128_ctr = CTR(aes_enc, &test_iv[0]);
        std::vector<uint8_t> actual(expected.size());
        size_t buffer_len{actual.size()};
        auto error = aes_128_ctr.Update(actual.data(), buffer_len, input.data(), input.size());
        ASSERT_EQ(error, CipherError::kSuccess);
        ASSERT_EQ(buffer_len, 16);
        ASSERT_THAT(actual, ContainerEq(expected));
    }
}

TEST(aes_128_ctr, simple_case)
{
    auto aes_enc = std::make_shared<AES128Enc>(&g_aes_128_ctr_test_key[0]);

    // NOLINTNEXTLINE
    uint8_t test_iv[] = {0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    const std::array<uint8_t, 17> input = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                           0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11};

    const std::vector<uint8_t> expected = {0x77, 0xB0, 0x8B, 0xB0, 0x94, 0x77, 0x62, 0xB8, 0x05,
                                           0xE7, 0xFF, 0x83, 0x9E, 0xE5, 0x6B, 0x9B, 0xA2};

    // Update 1 byte at a time.
    {
        auto aes_128_ctr = CTR_Stream(aes_enc, &test_iv[0]);
        for (size_t i = 0; i < input.size(); i++)
        {
            uint8_t buffer{};
            size_t buffer_len{1};
            auto error = aes_128_ctr.Update(&buffer, buffer_len, &input[i], 1);
            ASSERT_EQ(error, CipherError::kSuccess);
            ASSERT_EQ(buffer, expected[i]);
            ASSERT_EQ(buffer_len, 1);
        }
    }
    // Update the whole thing
    {
        auto aes_128_ctr = CTR_Stream(aes_enc, &test_iv[0]);
        std::vector<uint8_t> actual(expected.size());
        size_t buffer_len{actual.size()};
        auto error = aes_128_ctr.Update(actual.data(), buffer_len, input.data(), input.size());
        ASSERT_EQ(error, CipherError::kSuccess);
        ASSERT_EQ(buffer_len, input.size());
        ASSERT_THAT(actual, ContainerEq(expected));
    }
}

TEST(aes_128_ctr, counter_with_overflow)
{
    auto aes_enc = std::make_shared<AES128Enc>(&g_aes_128_ctr_test_key[0]);

    // NOLINTNEXTLINE
    uint8_t test_iv[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};

    const auto input = ([]() {
        std::array<uint8_t, 64> result{};
        for (int i = 0; i < result.size(); i++)
        {
            result[i] = i;
        }
        return result;
    })();

    const std::vector<uint8_t> expected = {0xC5, 0x5F, 0xB2, 0x71, 0xED, 0xE2, 0x42, 0x34, 0xF9, 0xCB, 0xEE, 0xB7, 0x0A,
                                           0x92, 0xD0, 0x20, 0xA5, 0xA0, 0x7C, 0x6E, 0xCB, 0x5B, 0x42, 0xD2, 0xC5, 0x7E,
                                           0x2C, 0x6F, 0x89, 0x2D, 0xDA, 0x8A, 0xBD, 0x0D, 0xF8, 0xB3, 0x3F, 0x4D, 0x0B,
                                           0x14, 0x71, 0x59, 0xB0, 0x71, 0x9E, 0x6C, 0xB8, 0x0B, 0x95, 0x97, 0x7D, 0x68,
                                           0xBF, 0x63, 0x91, 0x6B, 0xB6, 0x0E, 0x3D, 0xF8, 0xE3, 0x68, 0xE4, 0xF0};

    {
        auto aes_128_ctr = CTR_Stream(aes_enc, &test_iv[0]);
        std::vector<uint8_t> actual(expected.size());
        size_t buffer_len{actual.size()};
        auto error = aes_128_ctr.Update(actual.data(), buffer_len, input.data(), input.size());
        ASSERT_EQ(error, CipherError::kSuccess);
        ASSERT_EQ(buffer_len, input.size());
        ASSERT_THAT(actual, ContainerEq(expected));
    }
}

TEST(aes_128_ctr, counter_with_overflow_block_mode)
{
    auto aes_enc = std::make_shared<AES128Enc>(&g_aes_128_ctr_test_key[0]);

    // NOLINTNEXTLINE
    uint8_t test_iv[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};

    const auto input = ([]() {
        std::array<uint8_t, 64> result{};
        for (int i = 0; i < result.size(); i++)
        {
            result[i] = i;
        }
        return result;
    })();

    const std::vector<uint8_t> expected = {0xC5, 0x5F, 0xB2, 0x71, 0xED, 0xE2, 0x42, 0x34, 0xF9, 0xCB, 0xEE, 0xB7, 0x0A,
                                           0x92, 0xD0, 0x20, 0xA5, 0xA0, 0x7C, 0x6E, 0xCB, 0x5B, 0x42, 0xD2, 0xC5, 0x7E,
                                           0x2C, 0x6F, 0x89, 0x2D, 0xDA, 0x8A, 0xBD, 0x0D, 0xF8, 0xB3, 0x3F, 0x4D, 0x0B,
                                           0x14, 0x71, 0x59, 0xB0, 0x71, 0x9E, 0x6C, 0xB8, 0x0B, 0x95, 0x97, 0x7D, 0x68,
                                           0xBF, 0x63, 0x91, 0x6B, 0xB6, 0x0E, 0x3D, 0xF8, 0xE3, 0x68, 0xE4, 0xF0};

    {
        auto aes_128_ctr = CTR(aes_enc, &test_iv[0]);

        std::vector<uint8_t> actual{};

        constexpr size_t kMaxProcessLen = 13;
        std::array<uint8_t, 16> temp_buffer{};
        for (size_t bytes_left = input.size(); bytes_left != 0;)
        {
            auto input_len = std::min(bytes_left, kMaxProcessLen);
            auto output_len = temp_buffer.size();
            auto error =
                aes_128_ctr.Update(temp_buffer.data(), output_len, &input[input.size() - bytes_left], input_len);
            ASSERT_EQ(error, CipherError::kSuccess);
            actual.insert(actual.end(), temp_buffer.begin(), temp_buffer.begin() + output_len);
            bytes_left -= input_len;
        }

        ASSERT_THAT(actual, ContainerEq(expected));
    }
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
