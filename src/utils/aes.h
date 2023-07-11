#include <cstdint>
#include <memory>
#include <ranges>

namespace parakeet_crypto::aes
{

constexpr size_t kAes128BlockSize = 128 / 8;
constexpr size_t kAes192BlockSize = 192 / 8;
constexpr size_t kAes256BlockSize = 256 / 8;

template <size_t BLOCK_SIZE> class AES
{
  public:
    virtual ~AES() = default;

    virtual void process(uint8_t *buffer) = 0;

    [[nodiscard]] inline bool process(uint8_t *buffer, size_t len)
    {
        if (len % BLOCK_SIZE != 0)
        {
            return false;
        }

        uint8_t *p_cur = buffer;
        const uint8_t *p_end = p_cur + len;
        for (; p_cur < p_end; p_cur += BLOCK_SIZE)
        {
            process(p_cur);
        }
        return true;
    };

    template <typename Container> [[nodiscard]] inline bool process(Container &&container)
    {
        return process(container.data(), container.size());
    }
};

std::unique_ptr<AES<kAes128BlockSize>> make_aes_128_ecb_decryptor(const uint8_t *key);
std::unique_ptr<AES<kAes128BlockSize>> make_aes_128_ecb_encryptor(const uint8_t *key);

} // namespace parakeet_crypto::aes