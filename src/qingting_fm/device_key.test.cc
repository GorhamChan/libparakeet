#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "qingting_fm.h"

#include <algorithm>
#include <array>
#include <vector>

using namespace parakeet_crypto::qingting_fm;
using testing::ContainerEq;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(QingTingFM, device_key)
{
    DeviceSecretKey expected = {0x59, 0x64, 0x91, 0x77, 0x45, 0x46, 0x75, 0x6d,
                                0x08, 0x00, 0x08, 0x0a, 0x14, 0x12, 0x11, 0x12};
    auto actual = CreateDeviceSecretKey("product", "device", "manufacturer", "brand", "board", "model");
    ASSERT_THAT(actual, ContainerEq(expected));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
