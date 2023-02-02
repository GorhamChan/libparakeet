#include "parakeet-crypto/qmc2/footer_parser.h"
#include <memory>

namespace parakeet_crypto::qmc2
{

std::unique_ptr<FooterParseResult> ParseFileFooter(const uint8_t *file_footer, size_t len)
{
    return std::make_unique<FooterParseResult>();
}

} // namespace parakeet_crypto::qmc2
