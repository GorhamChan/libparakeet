#pragma once

#include "read_fixture.test.hh"
#include "test/read_fixture.test.hh"

#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/StreamHelper.h"
#include "gmock/gmock.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace parakeet_crypto::test
{

inline std::pair<TransformResult, std::vector<uint8_t>> transform_vector(std::vector<uint8_t> input_data,
                                                                         std::unique_ptr<ITransformer> &transformer)
{
    static const auto fixture_plain = read_fixture("sample_test_121529_32kbps.ogg");

    OutputMemoryStream output{};
    InputMemoryStream input{input_data};
    auto state = transformer->Transform(&output, &input);
    return std::make_pair(state, std::move(output.GetData()));
}

inline void should_decrypt_to_fixture(const char *input_fixture_name, std::unique_ptr<ITransformer> &transformer)
{
    static const auto fixture_plain = read_fixture("sample_test_121529_32kbps.ogg");

    auto fixture = read_fixture(input_fixture_name);
    auto [decryption_state, output] = transform_vector(fixture, transformer);
    ASSERT_EQ(decryption_state, TransformResult::OK);
    ASSERT_EQ(output.size(), fixture_plain.size());
    ASSERT_THAT(output, testing::ContainerEq(fixture_plain));
}

} // namespace parakeet_crypto::test
