#pragma once

#include <iostream>
#include <sstream>

#include "utils/logger_config.h"

namespace parakeet_crypto::logger
{

class NopLogger final
{
    template <typename T> NopLogger &operator<<(const T & /*data*/)
    {
        return *this;
    }
};

class DebugLogger final
{
  private:
    std::stringstream ss_{};

  public:
    DebugLogger(const DebugLogger &) = delete;
    DebugLogger(DebugLogger &&) = delete;
    DebugLogger &operator=(const DebugLogger &) = delete;
    DebugLogger &operator=(DebugLogger &&) = delete;

    DebugLogger(const char *tag)
    {
        ss_ << "parakeet[" << tag << "]: ";
    }
    ~DebugLogger()
    {
        std::cerr << ss_.str() << std::endl;
    }

    template <typename T> DebugLogger &operator<<(const T &data)
    {
        ss_ << data;
        return *this;
    }
};

#if PARAKEET_CRYPTO_LOGGING_ENABLE_WARN
inline DebugLogger WARN()
{
    return {"WARN"};
}
#else
inline NopLogger WARN()
{
    return {};
}
#endif

#if PARAKEET_CRYPTO_LOGGING_ENABLE_ERROR
inline DebugLogger ERROR()
{
    return {"ERROR"};
}
#else
inline NopLogger ERROR()
{
    return {};
}
#endif

} // namespace parakeet_crypto::logger
