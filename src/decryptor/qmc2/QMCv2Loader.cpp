#include "parakeet-crypto/decryptor/qmc2/QMCv2Loader.h"

#include "QMCv2RC4.h"
#include "QMCv2Utils.h"

#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <cassert>
#include <cstddef>

#include <stdexcept>
#include <vector>

namespace parakeet_crypto::decryptor {

namespace tencent::detail {

constexpr std::size_t kFirstSegmentSize = 0x80;
constexpr std::size_t kOtherSegmentSize = 0x1400;

enum class State {
    kDecryptFirstSegment = 0,
    kDecryptOtherSegment,
};

class QMCv2LoaderImpl : public StreamDecryptor {
   private:
    std::vector<uint8_t> key_;
    State state_ = State::kDecryptFirstSegment;
    std::shared_ptr<misc::tencent::QMCFooterParser> parser_;

    std::vector<uint8_t> S_;
    double key_hash_;

    QMCv2RC4 rc4;

   public:
    explicit QMCv2LoaderImpl(QMCv2KeyInput key) {
        assert(("QMCv2 key should not be empty", !key.empty()));
        key_.assign(key.begin(), key.end());
        S_.resize(key.size());
        key_hash_ = static_cast<double>(HashQMCv2Key(key));
        rc4.SetKey(key, key_hash_);
    }
    std::string GetName() const override { return "QMCv2(RC4)"; };

    void HandleFirstSegmentDecryption(const uint8_t*& in, std::size_t& len) {
        if (ReadBlock(in, len, kFirstSegmentSize)) {
            std::size_t n = key_.size();
            auto p_out = ExpandOutputBuffer(kFirstSegmentSize);
            const uint8_t* p_in = buf_in_.data();

            for (std::size_t i = 0; i < kFirstSegmentSize; i++) {
                auto seed = uint64_t{key_[i % n]};
                p_out[i] = p_in[i] ^ key_[GetSegmentKey(key_hash_, i, seed) % n];
            }

            ConsumeInput(kFirstSegmentSize);
            rc4.DiscardBytes(kFirstSegmentSize);
            state_ = State::kDecryptOtherSegment;
        }
    }

    void HandleOtherSegmentDecryption(const uint8_t* in, std::size_t len) {
        auto p_out = ExpandOutputBuffer(len);

        while (len > 0) {
            size_t segment_size_remain = offset_ % kOtherSegmentSize;
            if (segment_size_remain == 0) {
                rc4.NextSegment();
            }
            segment_size_remain = kOtherSegmentSize - segment_size_remain;

            std::size_t processed_len = std::min(segment_size_remain, len);
            rc4.Transform(std::span{p_out, processed_len}, std::span{in, processed_len});

            in += processed_len;
            p_out += processed_len;
            offset_ += processed_len;

            len -= processed_len;
        }
    }

    bool Write(const uint8_t* in, std::size_t len) override {
        if (state_ == State::kDecryptFirstSegment) {
            HandleFirstSegmentDecryption(in, len);
        }

        if (state_ == State::kDecryptOtherSegment) {
            HandleOtherSegmentDecryption(in, len);
        }

        return true;
    };

    bool End() override { return !InErrorState(); };
};

}  // namespace tencent::detail

std::unique_ptr<StreamDecryptor> CreateQMCv2Decryptor(tencent::QMCv2KeyInput key) {
    return std::make_unique<tencent::detail::QMCv2LoaderImpl>(key);
}

}  // namespace parakeet_crypto::decryptor
