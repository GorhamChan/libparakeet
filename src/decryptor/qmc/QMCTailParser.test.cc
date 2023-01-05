#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "parakeet-crypto/decryptor/qmc/QMCTailParser.h"
#include "test/helper.test.hh"

using ::testing::ContainerEq;
using ::testing::Return;

using namespace parakeet_crypto::qmc;

static const std::array<uint8_t, 16> kTestKey = {};

class DummyKeyCrypto : public KeyCrypto {
   public:
    DummyKeyCrypto() {}
    ~DummyKeyCrypto() override = default;

    MOCK_METHOD((std::optional<std::vector<uint8_t>>), Decrypt, (const std::string& ekey_b64), (const, override));
    MOCK_METHOD((std::optional<std::vector<uint8_t>>), Decrypt, (std::span<const uint8_t> ekey), (const, override));
};

TEST(QMCTailParser, PCClientTail) {
    std::vector<uint8_t> mocked_key = {1, 2, 3};
    std::vector<uint8_t> expected_key = mocked_key;  // NOLINT(performance-unnecessary-copy-initialization)

    auto test_data = std::to_array<uint8_t>({
        'u',  'n',  'u',  's', 'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0,                      // padding
        'R',  'q',  '1',  '6', 'X', 'z', '4', '6', 'x', 's', 'P', 'g', 'l', '6', 'm', 'D',  // key
        0x10, 0x00, 0x00, 0x00                                                              // size = 16
    });

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    std::string key_input = std::string("Rq16Xz46xsPgl6mD");
    EXPECT_CALL(*key_crypto_mock, Decrypt(key_input)).WillOnce(Return(mocked_key));

    auto parser = CreateTailParser(key_crypto_mock);
    auto result = parser->Parse(test_data);

    ASSERT_NE(result, std::nullopt);
    ASSERT_EQ(result->first, 20);
    ASSERT_THAT(result->second, ContainerEq(expected_key));
}

TEST(QMCTailParser, ShouldRejectSTag) {
    using ::testing::An;

    auto test_data = std::to_array<uint8_t>({
        'u',  'n',  'u',  's',  'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0,            // padding
        '5',  '8',  '7',  '4',  '8', '1', '3', '0', '7', ',', '2', ',',            // CSV Line of dummy data
        '0',  '0',  '7',  'A',  'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',  //
        0x00, 0x00, 0x00, 0x1A,                                                    // size = 0x1A (26)
        'S',  'T',  'a',  'g'                                                      // ending
    });

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    EXPECT_CALL(*key_crypto_mock, Decrypt(An<const std::string&>())).Times(0);

    auto parser = CreateTailParser(key_crypto_mock);
    auto result = parser->Parse(test_data);

    ASSERT_EQ(result, std::nullopt);
}

TEST(QMCTailParser, ShouldWorkWithQTag) {
    std::vector<uint8_t> mocked_key = {1, 2, 3};
    std::vector<uint8_t> expected_key = mocked_key;  // NOLINT(performance-unnecessary-copy-initialization)

    auto test_data = std::to_array<uint8_t>({
        'u', 'n', 'u', 's', 'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0,                           // padding
                                                                                              // CSV Record
        'R', 'q', '1', '6', 'X', 'z', '4', '6', 'x', 's', 'P', 'g', 'l', '6', 'm', 'D', ',',  //  - key
        '5', '8', '7', '4', '8', '1', '3', '0', '7', ',',                                     //  - song_id
        '2',                                                                                  //  - meta version?
                                                                                              //    always 2
        0x00, 0x00, 0x00, 0x1C,                                                               // sizeof(CSV Record)
                                                                                              //    = 0x1C (28)
        'Q', 'T', 'a', 'g'                                                                    // ending
    });

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    std::string key_input = std::string("Rq16Xz46xsPgl6mD");
    EXPECT_CALL(*key_crypto_mock, Decrypt(key_input)).WillOnce(Return(mocked_key));

    auto parser = CreateTailParser(key_crypto_mock);
    auto result = parser->Parse(test_data);

    ASSERT_NE(result, std::nullopt);
    ASSERT_EQ(result->first, 0x1C + 8);
    ASSERT_THAT(result->second, ContainerEq(expected_key));
}
