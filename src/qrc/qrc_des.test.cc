#include "qrc_des.h"

#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto::qrc;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(QRC_LRC, DecryptSomeData)
{
    std::array<uint8_t, 16> input = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    std::array<uint8_t, 16> expected_data = {0xFD, 0x0E, 0x64, 0x06, 0x65, 0xBE, 0x74, 0x13,
                                             0x77, 0x63, 0x3B, 0x02, 0x45, 0x4E, 0x70, 0x7A};

    QRC_DES des("TEST!KEY");
    ASSERT_TRUE(des.des_crypt(input.data(), input.size(), true));
    ASSERT_THAT(input, ContainerEq(expected_data));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
