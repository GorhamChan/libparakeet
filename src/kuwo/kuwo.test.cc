#include "parakeet-crypto/transformer/kuwo.h"
#include "parakeet-crypto/ITransformer.h"
#include "test/read_fixture.test.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Kuwo, EncryptAndDecrypt)
{
    auto fixture_sample = test::read_fixture("sample_test_121529_32kbps.ogg");
    std::vector<uint8_t> buffer(fixture_sample.size() + 0x1000);
    std::array<const uint8_t, 0x20> key = {0x7C, 0x31, 0x33, 0xF1, 0x37, 0x74, 0x70, 0x3E, 0x25, 0x39, 0x28,
                                           0x2D, 0xE9, 0xC8, 0xB3, 0xC3, 0xDF, 0x6D, 0x29, 0xB3, 0xB2, 0xA4,
                                           0x0B, 0xFF, 0x3E, 0x0F, 0x60, 0x7A, 0xE6, 0x78, 0xEE, 0x33};

    auto encryption_transformer = transformer::CreateKuwoEncryptionTransformer(key.data(), uint64_t{0x12345678});
    size_t encrypted_size = buffer.size();
    auto encryption_state =
        encryption_transformer->Transform(buffer.data(), encrypted_size, fixture_sample.data(), fixture_sample.size());
    buffer.resize(encrypted_size);
    ASSERT_EQ(encryption_state, TransformResult::OK);
    ASSERT_EQ(encrypted_size, fixture_sample.size() + 0x400);

    auto decryption_transformer = transformer::CreateKuwoDecryptionTransformer(key.data());
    size_t plain_len = buffer.size();
    auto decryption_state = decryption_transformer->Transform(buffer.data(), plain_len, buffer.data(), buffer.size());
    buffer.resize(plain_len);
    ASSERT_EQ(decryption_state, TransformResult::OK);
    ASSERT_THAT(buffer, ContainerEq(fixture_sample));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
