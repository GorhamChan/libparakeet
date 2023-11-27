#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qingting_fm.h"

#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(QingTingFM, TestSampleFile)
{
    auto transformer = transformer::CreateAndroidQingTingFMTransformer(
        ".p~!MTIzNDU2QEBA.qta", "DEV_PRODUCT", "DEV_DEVICE", "DEV_MANUFACTURER", "DEV_BRAND", "DEV_BOARD", "DEV_MODEL");
    test::should_decrypt_to_fixture("test_qtfm_MTIzNDU2QEBA.qta", transformer);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
