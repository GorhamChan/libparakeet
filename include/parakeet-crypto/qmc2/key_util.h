#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::qmc2
{

constexpr size_t kQMC2UseRC4Boundary = 300;

enum class QMC2EncryptionType
{
    MAP = 0,
    RC4 = 1,
};

inline QMC2EncryptionType GetEncryptionType(size_t key_size)
{
    if (key_size >= kQMC2UseRC4Boundary)
    {
        return QMC2EncryptionType::RC4;
    }

    return QMC2EncryptionType::MAP;
}

template <typename T> inline QMC2EncryptionType GetEncryptionType(T &&container)
{
    if (container.size() >= kQMC2UseRC4Boundary)
    {
        return QMC2EncryptionType::RC4;
    }

    return QMC2EncryptionType::MAP;
}

}; // namespace parakeet_crypto::qmc2
