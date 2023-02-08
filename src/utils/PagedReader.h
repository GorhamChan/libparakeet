#pragma once

#include "parakeet-crypto/IStream.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <utility>
#include <vector>

namespace parakeet_crypto::utils
{

class PagedReader
{
  private:
    IReadSeekable *input_{};

  public:
    PagedReader(IReadSeekable *input) : input_(input)
    {
    }

    // std::function<bool(size_t file_offset, uint8_t *buffer, size_t n)>
    template <typename Callback> [[nodiscard]] inline bool ReadInPages(size_t page_size, Callback callback)
    {
        size_t offset = input_->GetOffset();
        std::vector<uint8_t> buffer_container(page_size);
        auto *buffer = buffer_container.data();
        for (size_t len_left = input_->GetSize() - offset; len_left > 0;)
        {
            size_t process_len = std::min(len_left, page_size);
            if (!input_->ReadExact(buffer, process_len))
            {
                return false; // read failed
            }
            if (!callback(offset, buffer, process_len))
            {
                return false;
            }

            offset += process_len;
            len_left -= process_len;
        }

        return true;
    }

    template <typename Callback> [[nodiscard]] inline bool ReadInPages(Callback callback)
    {
        return ReadInPages(kDecryptionPageSize, std::move(callback));
    }
};

} // namespace parakeet_crypto::utils
