#pragma once

#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/StreamHelper.h"
#include "parakeet-crypto/qmc2/footer_parser.h"
#include "parakeet-crypto/qmc2/key_crypto.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

constexpr size_t kInitialFooterTestLe = 16;
constexpr uint8_t kTestSeed = 123;
constexpr std::array<uint8_t, 16> kTestEncV2Key1 = {
    11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28,
};
constexpr std::array<uint8_t, 16> kTestEncV2Key2 = {
    31, 32, 33, 34, 35, 36, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48,
};

namespace parakeet_crypto::test
{

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

template <typename T>
inline void DecryptQMC2Stream(std::vector<uint8_t> &vec_result, std::vector<uint8_t> &vec_encrypted,
                              T transformer_factory)
{
    auto len = vec_encrypted.size();
    auto key_crypto = qmc2::CreateKeyCrypto(kTestSeed, kTestEncV2Key1.data(), kTestEncV2Key2.data());
    auto footer_parser = qmc2::CreateQMC2FooterParser(std::move(key_crypto));
    auto footer = footer_parser->Parse(&vec_encrypted.at(len - kInitialFooterTestLe), kInitialFooterTestLe);
    ASSERT_EQ(footer->state, qmc2::FooterParseState::NeedMoreBytes);
    footer = footer_parser->Parse(&vec_encrypted.at(len - footer->footer_size), footer->footer_size);
    ASSERT_EQ(footer->state, qmc2::FooterParseState::OK);

    std::unique_ptr<ITransformer> transformer = transformer_factory(footer->key.data(), footer->key.size());
    InputMemoryStream full_reader{vec_encrypted};
    SlicedReadableStream reader{full_reader, 0, len - footer->footer_size};
    OutputMemoryStream writer{};
    ASSERT_EQ(transformer->Transform(&writer, &reader), TransformResult::OK);

    vec_result.swap(writer.GetData());
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

} // namespace parakeet_crypto::test
