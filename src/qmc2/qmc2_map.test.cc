#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"

#include "qmc2_keys.test.hh"

#include "test/read_fixture.test.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(QMC2_Map, DecryptionKey256)
{
    auto plain_file = test::read_fixture("sample_test_121529_32kbps.ogg");
    auto fixture_encrypted = test::read_fixture("test_qmc2_map.mgg");
    std::vector<uint8_t> decrypted{};
    test::DecryptQMC2Stream(decrypted, fixture_encrypted);
    ASSERT_EQ(decrypted.size(), plain_file.size());
    ASSERT_THAT(decrypted, ContainerEq(plain_file));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
