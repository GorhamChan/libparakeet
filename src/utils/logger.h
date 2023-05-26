#pragma once

#include <iostream>
#include <sstream>

#include "utils/logger_config.h"

namespace parakeet_crypto::logger
{

class NopLogger final
{
  public:
    template <typename T> NopLogger &operator<<(T && /*data*/)
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

    template <typename T> DebugLogger &operator<<(T &&data)
    {
        ss_ << data;
        return *this;
    }
};

#if PARAKEET_CRYPTO_LOGGING_ENABLE_INFO
inline DebugLogger INFO()
{
    return {"INFO"};
}
constexpr bool INFO_Enabled = true;
#else
inline NopLogger INFO()
{
    return {};
}
constexpr bool INFO_Enabled = false;
#endif

#if PARAKEET_CRYPTO_LOGGING_ENABLE_WARN
constexpr bool WARN_Enabled = true;
inline DebugLogger WARN()
{
    return {"WARN"};
}
#else
constexpr bool WARN_Enabled = false;
inline NopLogger WARN()
{
    return {};
}
#endif

#if PARAKEET_CRYPTO_LOGGING_ENABLE_ERROR
constexpr bool ERROR_Enabled = true;
inline DebugLogger ERROR()
{
    return {"ERROR"};
}
#else
constexpr bool ERROR_Enabled = false;
inline NopLogger ERROR()
{
    return {};
}
#endif

#if PARAKEET_CRYPTO_LOGGING_ENABLE_DEBUG
constexpr bool DEBUG_Enabled = true;
inline DebugLogger DEBUG()
{
    return {"DEBUG"};
}
#else
constexpr bool DEBUG_Enabled = false;
inline NopLogger DEBUG()
{
    return {};
}
#endif

} // namespace parakeet_crypto::logger
