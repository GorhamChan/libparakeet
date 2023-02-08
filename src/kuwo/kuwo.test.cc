#include "parakeet-crypto/transformer/kuwo.h"
#include "parakeet-crypto/ITransformer.h"
#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

std::array<const uint8_t, 0x20> kwm_test_key = {0x7C, 0x31, 0x33, 0xF1, 0x37, 0x74, 0x70, 0x3E, 0x25, 0x39, 0x28,
                                                0x2D, 0xE9, 0xC8, 0xB3, 0xC3, 0xDF, 0x6D, 0x29, 0xB3, 0xB2, 0xA4,
                                                0x0B, 0xFF, 0x3E, 0x0F, 0x60, 0x7A, 0xE6, 0x78, 0xEE, 0x33};

TEST(Kuwo, EncryptAndDecrypt)
{
    auto fixture_sample = test::read_fixture("sample_test_121529_32kbps.ogg");

    auto encryption_transformer =
        transformer::CreateKuwoEncryptionTransformer(kwm_test_key.data(), uint64_t{0x12345678});
    auto [encrypt_state, encrypted] = test::transform_vector(fixture_sample, encryption_transformer);
    ASSERT_EQ(encrypt_state, TransformResult::OK);
    ASSERT_EQ(encrypted.size(), fixture_sample.size() + 0x400);

    auto decryption_transformer = transformer::CreateKuwoDecryptionTransformer(kwm_test_key.data());
    auto [decrypt_state, decrypted] = test::transform_vector(encrypted, decryption_transformer);
    ASSERT_EQ(decrypt_state, TransformResult::OK);
    ASSERT_THAT(decrypted, ContainerEq(fixture_sample));
}

TEST(Kuwo, DecryptSampleFile)
{
    auto transformer = transformer::CreateKuwoDecryptionTransformer(kwm_test_key.data());
    test::should_decrypt_to_fixture("test_kuwo.kwm", transformer);
}

TEST(Kuwo, DecryptLocalFile)
{
    auto kwm_key = test::read_local_file("kwm.key");
    auto kwm_src = test::read_local_file("test.kwm");

    if (kwm_key.empty() || kwm_src.empty())
    {
        return; // skip test
    }

    auto decryption_transformer = transformer::CreateKuwoDecryptionTransformer(kwm_key.data());
    auto [state, data] = test::transform_vector(kwm_src, decryption_transformer);
    ASSERT_EQ(state, TransformResult::OK);
    ASSERT_TRUE(test::write_local_file("kwm_plain.bin", data));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
