#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/joox.h"
#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>

using testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN (*-magic-numbers,*-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(JOOX_v4, EncryptionAndDecryption)
{
    auto plain = test::read_fixture("sample_test_121529_32kbps.ogg");
    transformer::JooxConfig config{};
    config.install_uuid = "ffffffffffffffffffffffffffffffff";
    config.salt = {0xDA, 0x40, 0x7A, 0x0A, 0x02, 0x60, 0x45, 0x8B, 0xE1, 0x66, 0x2D, 0x3E, 0x37, 0x6D, 0xD1, 0x63};

    auto encryption_transformer = transformer::CreateJooxEncryptionV4Transformer(config);
    auto [en_state, en_data] = test::transform_vector(plain, encryption_transformer);
    ASSERT_EQ(en_state, TransformResult::OK);

    auto decryption_transformer = transformer::CreateJooxDecryptionV4Transformer(config);
    auto [de_state, de_data] = test::transform_vector(en_data, decryption_transformer);
    ASSERT_EQ(de_state, TransformResult::OK);

    ASSERT_THAT(de_data, ContainerEq(plain));
}

// NOLINTEND (*-magic-numbers,*-non-const-global-variables,cppcoreguidelines-owning-memory)
