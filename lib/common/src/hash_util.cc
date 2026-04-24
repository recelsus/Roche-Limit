#include "common/hash_util.h"

#include <openssl/hmac.h>
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

std::string hmac_sha256_hex(std::string_view key, std::string_view input) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    if (HMAC(EVP_sha256(),
             key.data(),
             static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(input.data()),
             input.size(),
             digest.data(),
             &digest_length) == nullptr) {
        throw std::runtime_error("failed to calculate HMAC-SHA256 hash");
    }

    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < digest_length; ++index) {
        stream << std::setw(2) << static_cast<int>(digest[index]);
    }
    return stream.str();
}

}  // namespace roche_limit::common
