#include "auth_core/api_key_hasher.h"

#include <sodium.h>

#include <cstdlib>
#include <stdexcept>
#include <string>

namespace roche_limit::auth_core {

namespace {

constexpr unsigned long long kArgonOpsLimit = 2;
constexpr std::size_t kArgonMemLimit = 19456ULL * 1024ULL;

void ensure_sodium_initialized() {
  static const bool initialized = [] { return sodium_init() >= 0; }();

  if (!initialized) {
    throw std::runtime_error("failed to initialize libsodium");
  }
}

std::string require_api_key_pepper() {
  const char *value = std::getenv("ROCHE_LIMIT_API_KEY_PEPPER");
  if (value == nullptr || *value == '\0') {
    throw std::runtime_error(
        "ROCHE_LIMIT_API_KEY_PEPPER is required for API key operations");
  }
  return value;
}

} // namespace

std::string hash_api_key(std::string_view api_key) {
  ensure_sodium_initialized();

  std::string api_key_hash;
  api_key_hash.resize(crypto_pwhash_STRBYTES);
  if (crypto_pwhash_str_alg(api_key_hash.data(), api_key.data(), api_key.size(),
                            kArgonOpsLimit, kArgonMemLimit,
                            crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("failed to hash api key");
  }

  api_key_hash.resize(std::char_traits<char>::length(api_key_hash.c_str()));
  return api_key_hash;
}

std::string api_key_lookup_hash(std::string_view api_key) {
  ensure_sodium_initialized();

  const auto pepper = require_api_key_pepper();
  const auto input = pepper + ":" + std::string(api_key);

  unsigned char digest[crypto_generichash_BYTES]{};
  if (crypto_generichash(digest, sizeof digest,
                         reinterpret_cast<const unsigned char *>(input.data()),
                         input.size(), nullptr, 0) != 0) {
    throw std::runtime_error("failed to calculate api key lookup hash");
  }

  std::string hex;
  hex.resize(sizeof digest * 2 + 1);
  sodium_bin2hex(hex.data(), hex.size(), digest, sizeof digest);
  hex.resize(sizeof digest * 2);
  return hex;
}

bool verify_api_key(std::string_view api_key, const std::string &api_key_hash) {
  ensure_sodium_initialized();
  return crypto_pwhash_str_verify(api_key_hash.c_str(), api_key.data(),
                                  api_key.size()) == 0;
}

} // namespace roche_limit::auth_core
