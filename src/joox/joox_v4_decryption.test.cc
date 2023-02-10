#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/joox.h"
#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>

using namespace parakeet_crypto;

// NOLINTBEGIN (*-magic-numbers,*-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(JOOX_v4, DecryptionFixture)
{
    transformer::JooxConfig config{};
    config.install_uuid = "ffffffffffffffffffffffffffffffff";
    config.salt = {0xDA, 0x40, 0x7A, 0x0A, 0x02, 0x60, 0x45, 0x8B, 0xE1, 0x66, 0x2D, 0x3E, 0x37, 0x6D, 0xD1, 0x63};
    auto transformer = transformer::CreateJooxDecryptionV4Transformer(config);
    test::should_decrypt_to_fixture("joox_[E!04].ofl_en", transformer);
}

// NOLINTEND (*-magic-numbers,*-non-const-global-variables,cppcoreguidelines-owning-memory)
