#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ximalaya.h"
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

TEST(Ximalaya, BasicDecryption)
{
    std::array<uint8_t, 12> key{};
    transformer::CreateXimalayaDecryptionTransformer(key.data(), key.data(), key.size());
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
