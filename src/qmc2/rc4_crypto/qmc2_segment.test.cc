#include "qmc2_segment.h"
#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"

#include "test/read_fixture.test.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

using namespace parakeet_crypto::qmc2_rc4;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(QMC2_Segment, GetKey)
{
    SegmentKeyImpl segment_key{516402887};
    ASSERT_EQ(segment_key.GetKey(51, 35), uint64_t{28373784});
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
