#include "parakeet-crypto/transformer/kgm.h"
#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
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
#include <memory>
#include <vector>

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

const transformer::KGMConfig &GetTestKGMConfig()
{
    static auto config = ([]() {
        transformer::KGMConfig config{};
        config.slot_keys = {{1, {'0', '9', 'A', 'Z'}}};
        config.v4.slot_key_table = test::read_fixture("test_kgm_v4_slotkey_table.bin");
        config.v4.file_key_table = test::read_fixture("test_kgm_v4_filekey_table.bin");
        return config;
    })();

    return config;
}

TEST(KGMCrypto, Type2)
{
    auto transformer = transformer::CreateKGMDecryptionTransformer(GetTestKGMConfig());
    test::should_decrypt_to_fixture("test_kgm_v2.kgm", transformer);
}

TEST(KGMCrypto, Type3)
{
    auto transformer = transformer::CreateKGMDecryptionTransformer(GetTestKGMConfig());
    test::should_decrypt_to_fixture("test_kgm_v3.kgm", transformer);
}

TEST(KGMCrypto, Type4)
{
    auto transformer = transformer::CreateKGMDecryptionTransformer(GetTestKGMConfig());
    test::should_decrypt_to_fixture("test_kgm_v4.kgm", transformer);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
