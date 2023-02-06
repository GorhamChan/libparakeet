#include "parakeet-crypto/transformer/ncm.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"
#include "test/read_fixture.test.hh"

#include <cstdio>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(NCM, TestDecryption)
{
    auto fixture_plain = test::read_fixture("sample_test_121529_32kbps.ogg");
    auto fixture_ncm = test::read_fixture("test.ncm");

    static constexpr std::array<const uint8_t, 16> ncm_key = {0x80, 0x88, 0x6A, 0x09, 0x09, 0x2E, 0x28, 0x7F,
                                                              0xB1, 0x66, 0xB3, 0x8D, 0x0C, 0xEB, 0xC7, 0x1A};

    std::vector<uint8_t> buffer(fixture_ncm.size() + 0x100);
    auto ncm_transformer = transformer::CreateNeteaseNCMDecryptionTransformer(ncm_key.data());
    size_t plain_len = buffer.size();
    auto decryption_state =
        ncm_transformer->Transform(buffer.data(), plain_len, fixture_ncm.data(), fixture_ncm.size());
    buffer.resize(plain_len);
    ASSERT_EQ(decryption_state, TransformResult::OK);
    ASSERT_EQ(plain_len, fixture_plain.size());
    ASSERT_THAT(buffer, ContainerEq(fixture_plain));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
