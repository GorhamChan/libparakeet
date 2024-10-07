#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "parakeet-crypto/qmc2/footer_parser.h"
#include "parakeet-crypto/qmc2/key_crypto.h"

using ::testing::ContainerEq;
using ::testing::Return;

using namespace parakeet_crypto::qmc2;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

// NOLINTBEGIN(*-non-private-member-variables-in-classes)

class DummyKeyCrypto : public IKeyCrypto
{
  public:
    DummyKeyCrypto() = default;
    ~DummyKeyCrypto() override = default;

    MOCK_METHOD((std::vector<uint8_t>), Decrypt, (const uint8_t *key, size_t len), (override));
    MOCK_METHOD((std::vector<uint8_t>), Encrypt, (const uint8_t *key, size_t len, KeyVersion version), (override));
};
// NOLINTEND(*-non-private-member-variables-in-classes)

TEST(QMCTailParser, PCClientTail)
{
    const std::vector<uint8_t> mocked_key = {1, 2, 3};
    const std::vector<uint8_t> expected_key = mocked_key; // NOLINT(performance-unnecessary-copy-initialization)

    std::vector<uint8_t> test_data = {
        'u',  'n',  'u',  's', 'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0,                     // padding
        'R',  'q',  '1',  '6', 'X', 'z', '4', '6', 'x', 's', 'P', 'g', 'l', '6', 'm', 'D', // key
        0x10, 0x00, 0x00, 0x00                                                             // size = 16
    };

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    EXPECT_CALL(*key_crypto_mock, Decrypt(&test_data.at(12), 16)).WillOnce(Return(mocked_key));

    auto parser = CreateQMC2FooterParser(key_crypto_mock);
    auto result = parser->Parse(test_data.data(), test_data.size());

    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->state, FooterParseState::OK);
    ASSERT_EQ(result->footer_size, 20);
    ASSERT_THAT(result->key, ContainerEq(expected_key));
}

TEST(QMCTailParser, ShouldRejectSTag)
{
    using ::testing::An;

    std::vector<uint8_t> test_data = {
        'u',  'n',  'u',  's',  'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0,           // padding
        '5',  '8',  '7',  '4',  '8', '1', '3', '0', '7', ',', '2', ',',           // CSV Line of dummy data
        '0',  '0',  '7',  'A',  'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', //
        0x00, 0x00, 0x00, 0x1A,                                                   // size = 0x1A (26)
        'S',  'T',  'a',  'g'                                                     // ending
    };

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    EXPECT_CALL(*key_crypto_mock, Decrypt(An<const uint8_t *>(), An<size_t>())).Times(0);

    auto parser = CreateQMC2FooterParser(key_crypto_mock);
    auto result = parser->Parse(test_data.data(), test_data.size());

    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->state, FooterParseState::UnsupportedAndroidClientSTag);
}

TEST(QMCTailParser, ShouldWorkWithQTag)
{
    const std::vector<uint8_t> mocked_key = {1, 2, 3};
    const std::vector<uint8_t> expected_key = mocked_key; // NOLINT(performance-unnecessary-copy-initialization)

    std::vector<uint8_t> test_data = {
        'u', 'n', 'u', 's', 'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0,                          // padding
                                                                                             // CSV Record
        'R', 'q', '1', '6', 'X', 'z', '4', '6', 'x', 's', 'P', 'g', 'l', '6', 'm', 'D', ',', //  - key
        '5', '8', '7', '4', '8', '1', '3', '0', '7', ',',                                    //  - song_id
        '2',                                                                                 //  - meta version?
                                                                                             //    always 2
        0x00, 0x00, 0x00, 0x1C,                                                              // size of CSV Record
        'Q', 'T', 'a', 'g'                                                                   // ending
    };

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    EXPECT_CALL(*key_crypto_mock, Decrypt(&test_data.at(12), 16)).WillOnce(Return(mocked_key));

    auto parser = CreateQMC2FooterParser(key_crypto_mock);
    auto result = parser->Parse(test_data.data(), test_data.size());

    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->state, FooterParseState::OK);
    ASSERT_EQ(result->footer_size, 0x1C + 8);
    ASSERT_THAT(result->key, ContainerEq(expected_key));
}

TEST(QMCTailParser, ShouldWorkWithMusicEx)
{
    const std::vector<uint8_t> mocked_key = {1, 2, 3};
    const std::vector<uint8_t> expected_key = mocked_key; // NOLINT(performance-unnecessary-copy-initialization)

    std::vector<uint8_t> test_data = {
        // dummy data
        'u', 'n', 'u', 's', 'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0, // padding

        // data start
        0x12, 0x34, 0x56, 0x78, // unused
        0x02, 0x00, 0x00, 0x00, // unused
        0x05, 0x00, 0x00, 0x00, // unused

        // mid
        'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        // media file
        'F', 0, '0', 0, 'M', 0, '0', 0, '0', 0, '0', 0, '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6', 0, '7', 0, '8', 0,
        '9', 0, 'Z', 0, 'Z', 0, 'Z', 0, '.', 0, 'm', 0, 'f', 0, 'l', 0, 'a', 0, 'c', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,

        0xFF, 0xFF, 0xFF, 0xFF, // unused

        // tail magic
        0xC0, 0x00, 0x00, 0x00,               // size of the struct
        0x01, 0x00, 0x00, 0x00,               // version
        'm', 'u', 's', 'i', 'c', 'e', 'x', 0, // tag
    };

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    auto parser = CreateQMC2FooterParser(key_crypto_mock);
    auto result = parser->Parse(test_data.data(), test_data.size());

    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->state, FooterParseState::OK);
    ASSERT_EQ(result->footer_size, 0xC0);
    ASSERT_STREQ(result->media_file_name.c_str(), "F0M000123456789ZZZ.mflac");
    ASSERT_THAT(result->key, ContainerEq(std::vector<uint8_t>(0)));
}

TEST(QMCTailParser, ShouldWorkWithMusicExTruncation)
{
    const std::vector<uint8_t> mocked_key = {1, 2, 3};
    const std::vector<uint8_t> expected_key = mocked_key; // NOLINT(performance-unnecessary-copy-initialization)

    std::vector<uint8_t> test_data = {
        // dummy data
        'u', 'n', 'u', 's', 'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0, // padding

        // data start
        0x12, 0x34, 0x56, 0x78, // unused
        0x02, 0x00, 0x00, 0x00, // unused
        0x05, 0x00, 0x00, 0x00, // unused

        // mid
        'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0, 'A', 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        // media file (Z should be removed)
        'F', 0, '0', 0, 'M', 0, '0', 0, '0', 0, '0', 0, '0', 0, '1', 0, '1', 0, '1', 0, '1', 0, '2', 0, '2', 0, '2', 0,
        '2', 0, '3', 0, '3', 0, '3', 0, '3', 0, '4', 0, '4', 0, '4', 0, '4', 0, '5', 0, '5', 0, '5', 0, '5', 0, '6', 0,
        '6', 0, '6', 0, '6', 0, '7', 0, '7', 0, '7', 0, '7', 0, '8', 0, '8', 0, '8', 0, '8', 0, '9', 0, '9', 0, '9', 0,
        '9', 0, '.', 0, 'm', 0, 'f', 0, 'l', 0, 'a', 0, 'c', 0, 'Z', 0,

        0xFF, 0xFF, 0xFF, 0xFF, // unused

        // tail magic
        0xC0, 0x00, 0x00, 0x00,               // size of the struct
        0x01, 0x00, 0x00, 0x00,               // version
        'm', 'u', 's', 'i', 'c', 'e', 'x', 0, // tag
    };

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    auto parser = CreateQMC2FooterParser(key_crypto_mock);
    auto result = parser->Parse(test_data.data(), test_data.size());

    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->state, FooterParseState::OK);
    ASSERT_EQ(result->footer_size, 0xC0);
    ASSERT_STREQ(result->media_file_name.c_str(), "F0M0000111122223333444455556666777788889999.mflac");
    ASSERT_THAT(result->key, ContainerEq(std::vector<uint8_t>(0)));
}

TEST(QMCTailParser, ShouldIgnoreMusicExWithLargeBuffer)
{
    const std::vector<uint8_t> mocked_key = {1, 2, 3};
    const std::vector<uint8_t> expected_key = mocked_key; // NOLINT(performance-unnecessary-copy-initialization)

    std::vector<uint8_t> test_data = {
        // dummy data
        'u', 'n', 'u', 's', 'e', 'd', 0b0, 'd', 'a', 't', 'a', 0b0, // padding

        // tail magic
        0x00, 0x10, 0x00, 0x00,               // size of the struct
        0x01, 0x00, 0x00, 0x00,               // version
        'm', 'u', 's', 'i', 'c', 'e', 'x', 0, // tag
    };

    auto key_crypto_mock = std::make_shared<DummyKeyCrypto>();
    auto parser = CreateQMC2FooterParser(key_crypto_mock);
    auto result = parser->Parse(test_data.data(), test_data.size());

    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->state, FooterParseState::MusicExBufferOverflow);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
