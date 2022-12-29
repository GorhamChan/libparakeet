#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "parakeet-crypto/decryption/tencent/QMCv2Loader.h"
#include "internal/EndianHelper.h"
#include "parakeet-crypto/misc/QMCFooterParser.h"
#include "parakeet-crypto/misc/QMCKeyDeriver.h"
#include "parakeet-crypto/utils/base64.h"
#include "test/helper.test.hh"

using ::testing::ElementsAreArray;

using namespace parakeet_crypto::decryption::tencent;
using namespace parakeet_crypto;
using namespace parakeet_crypto::misc::tencent;

TEST(QMCv2, RC4Cipher) {
  std::vector<uint8_t> test_data(test::kSize4MiB);
  test::GenerateTestData(test_data, "qmcv2 rc4 cipher data");

  std::vector<uint8_t> ekey;
  std::vector<uint8_t> file_key(512);
  std::vector<uint8_t> parsed_file_key;
  test::GenerateTestData(file_key, "qmcv2 rc4 cipher key");

  // chosen by fair dice roll.
  // guaranteed to be random.
  std::fill_n(file_key.begin(), 8, '4');

  std::shared_ptr<QMCKeyDeriver> key_deriver = QMCKeyDeriver::Create(
      123, parakeet_crypto::misc::tencent::QMCEncV2Stage1Key{}, parakeet_crypto::misc::tencent::QMCEncV2Stage2Key{});
  ASSERT_EQ(key_deriver->ToEKey(ekey, file_key), true);
  ASSERT_EQ(key_deriver->FromEKey(parsed_file_key, ekey), true);
  ASSERT_THAT(parsed_file_key, ElementsAreArray(file_key));

  auto ekey_b64 = utils::Base64Encode(ekey);
  ekey.assign(ekey_b64.begin(), ekey_b64.end());
  uint32_t payload_size = SwapHostToLittleEndian(static_cast<uint32_t>(ekey.size()));
  ekey.insert(ekey.end(), reinterpret_cast<uint8_t*>(&payload_size),
              reinterpret_cast<uint8_t*>(&payload_size) + sizeof(payload_size));

  test_data.insert(test_data.end(), ekey.begin(), ekey.end());

  auto loader = QMCv2Loader::Create(QMCFooterParser::Create(key_deriver));
  auto result = test::DecryptTestContent(std::move(loader), test_data);

  test::VerifyHash(result, "757fc9aa94ab48295b106a16452b7da7b90395be8e3132a077b6d2a9ea216838");
}
