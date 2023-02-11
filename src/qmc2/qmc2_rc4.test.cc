#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"

#include "qmc2_keys.test.hh"

#include "test/read_fixture.test.hh"

#include <cstdio>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(QMC2_RC4, BasicKeyEncV1Decryption)
{
    auto plain_file = test::read_fixture("sample_test_121529_32kbps.ogg");
    auto fixture_encrypted = test::read_fixture("test_qmc2_rc4.mgg");
    std::vector<uint8_t> decrypted{};
    test::DecryptQMC2Stream(decrypted, fixture_encrypted);
    ASSERT_EQ(decrypted.size(), plain_file.size());
    ASSERT_THAT(decrypted, ContainerEq(plain_file));
}

TEST(QMC2_RC4, BasicKeyEncV2Decryption)
{
    auto plain_file = test::read_fixture("sample_test_121529_32kbps.ogg");
    auto fixture_encrypted = test::read_fixture("test_qmc2_rc4_EncV2.mgg");
    std::vector<uint8_t> decrypted{};
    test::DecryptQMC2Stream(decrypted, fixture_encrypted);
    ASSERT_EQ(decrypted.size(), plain_file.size());
    ASSERT_THAT(decrypted, ContainerEq(plain_file));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
