#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <vector>

#include "XimalayaScrambleTableGeneration.h"
#include "test/helper.test.hh"

using ::testing::ElementsAreArray;

using namespace parakeet_crypto::decryption::ximalaya;
using namespace parakeet_crypto;

TEST(Ximalaya, ScrambleTable) {
  auto result = generate_ximalaya_scramble_table(0.334455, 3.998877, 5);
  uint16_t expected[] = {1, 3, 2, 4, 0};
  ASSERT_THAT(result, ElementsAreArray(expected));
}
