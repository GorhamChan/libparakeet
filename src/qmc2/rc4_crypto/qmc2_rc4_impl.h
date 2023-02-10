#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto::qmc2_rc4
{

class RC4
{
  public:
    /**
     * @brief Create RC4 State from key
     *
     * @param key
     * @param key_len
     * @return std::vector<uint8_t> Initialized RC4 state.
     */
    static std::vector<uint8_t> CreateStateFromKey(const uint8_t *key, size_t key_len)
    {
        std::vector<uint8_t> s(key_len); // NOLINT(readability-identifier-length)

        for (size_t i = 0; i < key_len; i++)
        {
            s[i] = static_cast<uint8_t>(i);
        }

        size_t j = 0; // NOLINT(readability-identifier-length)
        for (size_t i = 0; i < key_len; i++)
        {
            j = (size_t{j} + size_t{s[i]} + size_t{key[i % key_len]}) % key_len;
            std::swap(s[i], s[j]);
        }

        return s;
    }

  private:
    std::vector<uint8_t> s_{};
    size_t i_{0};
    size_t j_{0};

    inline void MoveStateForward()
    {
        auto len = s_.size();
        i_ = (i_ + 1) % len;
        j_ = (j_ + s_[i_]) % len;
        std::swap(s_[i_], s_[j_]);
    }

  public:
    RC4(std::vector<uint8_t> state, size_t discard) : s_(std::move(state))
    {
        for (size_t i = 0; i < discard; i++)
        {
            MoveStateForward();
        }
    }

    uint8_t Next()
    {
        MoveStateForward();
        auto index = (s_[i_] + s_[j_]) % s_.size();
        return s_[index];
    }
};

} // namespace parakeet_crypto::qmc2_rc4
