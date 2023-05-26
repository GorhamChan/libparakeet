#include "parakeet-crypto/transformer/migu3d.h"
#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

#include <cstdio>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Migu3D, DecryptionTest)
{
    auto transformer = transformer::CreateKeylessMiguTransformer();
    test::should_decrypt_to_fixture("test.mg3d", transformer);
}

TEST(Migu3D, KeylessDecryptionTest)
{
    std::array<uint8_t, 16> test_salt = {'l', 'i', 'b', 'p', 'a', 'r', 'a', 'k',
                                         'e', 'e', 't', '/', 't', 'e', 's', 't'};
    std::array<uint8_t, 16> test_file_key = {'0', '0', '0', '0', '1', '1', '1', '1',
                                             '2', '2', '2', '2', '3', '3', '3', '3'};
    auto transformer = transformer::CreateMiguTransformer(test_salt.data(), test_file_key.data());
    test::should_decrypt_to_fixture("test.mg3d", transformer);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
