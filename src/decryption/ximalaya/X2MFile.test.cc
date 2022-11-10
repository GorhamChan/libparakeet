#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <vector>

#include "parakeet-crypto/decryption/ximalaya/XimalayaFileLoader.h"
#include "parakeet-crypto/endian.h"
#include "test/helper.test.hh"

using ::testing::ElementsAreArray;

using namespace parakeet_crypto::decryption::ximalaya;
using namespace parakeet_crypto;

TEST(Ximalaya, X2MTestCase) {
  std::vector<uint8_t> test_data(test::kSize1MiB);
  test::GenerateTestData(test_data, "x2m-test-data");

  X2MContentKey x2m_content_key;
  test::GenerateTestData(x2m_content_key, "x2m content key");

  ScrambleTable x2m_scramble_table;
  for (uint16_t i = 0; i < x2m_scramble_table.size(); i++) {
    x2m_scramble_table[i] = i;
  }
  std::vector<uint8_t> x2m_scramble_seed(x2m_scramble_table.size() * 2);
  test::GenerateTestData(x2m_scramble_seed, "x2m seed");
  for (std::size_t i = 0; i < x2m_scramble_table.size(); i++) {
    std::size_t j = ReadLittleEndian<uint16_t>(&x2m_scramble_seed[i * 2]) % x2m_scramble_table.size();
    std::swap(x2m_scramble_table[i], x2m_scramble_table[j]);
  }

  auto result = test::DecryptTestContent(XimalayaFileLoader::Create(x2m_content_key, x2m_scramble_table), test_data);

  test::VerifyHash(result, "fd1ac1c4750f48b8d3c9562013f1c3202b12e45137b344995eda32a4f6b8a61f");
}
