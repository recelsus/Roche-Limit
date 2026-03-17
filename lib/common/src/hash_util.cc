#include "common/hash_util.h"

#include <openssl/sha.h>

#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace roche_limit::common {

std::string sha256_hex(std::string_view input) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (SHA256(reinterpret_cast<const unsigned char*>(input.data()),
               input.size(),
               digest.data()) == nullptr) {
        throw std::runtime_error("failed to calculate SHA-256 hash");
    }

    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : digest) {
        stream << std::setw(2) << static_cast<int>(byte);
    }
    return stream.str();
}

}  // namespace roche_limit::common
