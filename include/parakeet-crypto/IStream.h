#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto
{

enum class SeekDirection
{
    SEEK_FILE_BEGIN = 0,
    SEEK_CURRENT_POSITION = 1,
    SEEK_FILE_END = 2,
};

class IReadSeekable
{
  public:
    virtual ~IReadSeekable() = default;
    [[nodiscard("validate it")]] virtual size_t Read(uint8_t *buffer, size_t len) = 0;
    virtual void Seek(size_t position, SeekDirection seek_dir) = 0;
    virtual size_t GetSize() = 0;
    virtual size_t GetOffset() = 0;

    // Helpers
    [[nodiscard("check if we've read them all")]] bool ReadExact(uint8_t *buffer, size_t len)
    {
        auto bytes_read = Read(buffer, len);
        return bytes_read == len;
    }

    [[nodiscard("use it")]] std::vector<uint8_t> Read(size_t len)
    {
        std::vector<uint8_t> result(len, 0);
        auto new_size = Read(result.data(), result.size());
        result.resize(new_size);
        return result;
    }
};

class IWriteable
{
  public:
    virtual ~IWriteable() = default;
    [[nodiscard]] virtual bool Write(const uint8_t *buffer, size_t len) = 0;
};

} // namespace parakeet_crypto
