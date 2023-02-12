#include "parakeet-crypto/transformer/xiami.h"
#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ncm.h"
#include "parakeet-crypto/transformer/qmc.h"
#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

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

void GenerateTestData()
{
    std::array<uint8_t, 0x10> header{'i',  'f',  'm',  't',  'O',  'g', 'g', 's', //
                                     0xfe, 0xfe, 0xfe, 0xfe, 0x20, 0,   0,   0x7f};

    auto plain = test::read_fixture("sample_test_121529_32kbps.ogg");
    plain.insert(plain.begin(), header.begin(), header.end());
    for (auto it = plain.begin() + 0x30; it < plain.end(); it++)
    {
        *it = 0x7F + 1 - *it;
    }
    test::write_local_file("../fixture/test.xm", plain);
}

TEST(Xiami, TestDecryption)
{
    auto transformer = transformer::CreateXiamiDecryptionTransformer();
    test::should_decrypt_to_fixture("test.xm", transformer);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
