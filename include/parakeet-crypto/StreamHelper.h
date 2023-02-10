#include "IStream.h"
#include "parakeet-crypto/IStream.h"

#include <fstream>
#include <memory>
#include <utility>

namespace parakeet_crypto
{

class InputFileStream final : public IReadSeekable
{
  private:
    std::ifstream &ifs_;

  public:
    InputFileStream(std::ifstream &ifs) : ifs_(ifs)
    {
    }

    size_t Read(uint8_t *buffer, size_t len) override
    {
        ifs_.read(reinterpret_cast<char *>(buffer), static_cast<std::streamsize>(len)); // NOLINT(*-reinterpret-cast)
        return ifs_.gcount();
    }
    void Seek(size_t position, SeekDirection seek_dir) override
    {
        ifs_.seekg(static_cast<std::streamsize>(position),
                   seek_dir == SeekDirection::CURRENT_POSITION ? std::ifstream::cur
                   : seek_dir == SeekDirection::FILE_BEGIN     ? std::ifstream::beg
                                                               : std::ifstream::end);
    }
    size_t GetSize() override
    {
        auto pos = ifs_.tellg();
        ifs_.seekg(0, std::ifstream::end);
        auto size = ifs_.tellg();
        ifs_.seekg(pos, std::ifstream::beg);
        return size;
    }
    size_t GetOffset() override
    {
        return ifs_.tellg();
    }
};

class OutputFileStream final : public IWriteable
{
  private:
    std::ofstream &ofs_;

  public:
    OutputFileStream(std::ofstream &ofs) : ofs_(ofs)
    {
    }

    void Write(const uint8_t *buffer, size_t len) override
    {
        ofs_.write(reinterpret_cast<const char *>(buffer), // NOLINT(*-reinterpret-cast)
                   static_cast<std::streamsize>(len));
    }
};

class InputMemoryStream final : public IReadSeekable
{
  public:
    std::vector<uint8_t> &GetData()
    {
        return data_;
    }

  private:
    std::vector<uint8_t> data_;
    size_t offset_{0};

  public:
    InputMemoryStream() = default;
    InputMemoryStream(std::vector<uint8_t> &data) : data_(data)
    {
    }

    size_t Read(uint8_t *buffer, size_t len) override
    {
        auto actual_read = std::min(len, data_.size() - offset_);
        std::copy_n(&data_.at(offset_), actual_read, buffer);
        offset_ += actual_read;
        return actual_read;
    }
    void Seek(size_t position, SeekDirection seek_dir) override
    {
        size_t next_offset{0};
        switch (seek_dir)
        {
        case SeekDirection::FILE_BEGIN:
            next_offset = position;
            break;
        case SeekDirection::CURRENT_POSITION:
            next_offset = offset_ + position;
            break;
        case SeekDirection::FILE_END_BACKWARDS:
            next_offset = data_.size() + position;
            break;
        default:
            return;
        }

        offset_ = std::max(std::min(next_offset, data_.size()), size_t{0});
    }
    size_t GetSize() override
    {
        return data_.size();
    }
    size_t GetOffset() override
    {
        return offset_;
    }
};

class SlicedReadableStream final : public IReadSeekable
{
  private:
    std::shared_ptr<IReadSeekable> parent_;
    size_t start_{};
    size_t end_{};

  public:
    SlicedReadableStream(std::shared_ptr<IReadSeekable> parent, size_t start_index, size_t end_index)
        : parent_(std::move(parent)), start_(start_index), end_(end_index)
    {
    }

    size_t Read(uint8_t *buffer, size_t len) override
    {
        auto offset = GetOffset();

        if (offset < start_)
        {
            offset = start_;
            parent_->Seek(start_, SeekDirection::FILE_BEGIN);
        }

        size_t read_len = std::min(end_ - offset, len);
        return parent_->Read(buffer, read_len);
    }

    void Seek(size_t position, SeekDirection seek_dir) override
    {
        size_t next_offset{0};
        switch (seek_dir)
        {
        case SeekDirection::FILE_BEGIN:
            next_offset = position;
            break;
        case SeekDirection::CURRENT_POSITION:
            next_offset = parent_->GetOffset() + position;
            break;
        case SeekDirection::FILE_END_BACKWARDS:
            next_offset = end_ + position;
            break;
        default:
            return;
        }

        parent_->Seek(std::max(std::min(next_offset, end_), start_), SeekDirection::FILE_BEGIN);
    }
    size_t GetSize() override
    {
        return end_ - start_;
    }
    size_t GetOffset() override
    {
        return std::min(parent_->GetOffset() - start_, end_);
    }
};

class OutputMemoryStream final : public IWriteable
{
  public:
    std::vector<uint8_t> &GetData()
    {
        return data_;
    }

  private:
    std::vector<uint8_t> data_{};
    size_t offset_{0};

  public:
    OutputMemoryStream() = default;
    OutputMemoryStream(std::vector<uint8_t> &data) : data_(data)
    {
    }

    void Write(const uint8_t *buffer, size_t len) override
    {
        data_.insert(data_.end(), buffer, buffer + len);
    }
};

class CappedOutputStream final : public IWriteable
{
  private:
    size_t bytes_left_{0};
    std::shared_ptr<IWriteable> parent_;

  public:
    CappedOutputStream(std::shared_ptr<IWriteable> parent, size_t capacity)
        : parent_(std::move(parent)), bytes_left_(capacity)
    {
    }

    void Write(const uint8_t *buffer, size_t len) override
    {
        auto bytes_to_copy = std::min(len, bytes_left_);
        if (bytes_to_copy > 0)
        {
            parent_->Write(buffer, bytes_to_copy);
            bytes_left_ -= bytes_to_copy;
        }
    }
};

}; // namespace parakeet_crypto
