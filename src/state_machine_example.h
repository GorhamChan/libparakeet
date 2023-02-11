#pragma once

#include "parakeet-crypto/ITransformer.h"

namespace parakeet_crypto::example
{

class SomeTransformer : parakeet_crypto::ITransformer
{
  private:
    enum class State
    {
        STATE1,
        STATE2,
    };
    State state_{State::STATE1};

  public:
    TransformResult HandleState1(                                    // NOLINT(*-functions-to-static)
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        // TODO: Add handler code
        return TransformResult::OK;
    }

    TransformResult HandleState2(                                    // NOLINT(*-functions-to-static)
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        // TODO: Add handler code
        return TransformResult::OK;
    }

    TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) override
    {

        if (output_len < input_len)
        {
            output_len = input_len;
            return TransformResult::ERROR_INSUFFICIENT_OUTPUT;
        }

        size_t bytes_written{0};
        TransformResult result{TransformResult::OK};
        while (result == TransformResult::OK && input_len > 0)
        {
            switch (state_)
            {
            case State::STATE1:
                result = HandleState1(bytes_written, output, output_len, input, input_len);
                break;
            case State::STATE2:
                result = HandleState2(bytes_written, output, output_len, input, input_len);
                break;
            }
        }
        return result;
    }
};

} // namespace parakeet_crypto::example
