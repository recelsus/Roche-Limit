#include "auth_core/password_hasher.h"

#include <sodium.h>

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

} // namespace

std::string hash_password(std::string_view password) {
  ensure_sodium_initialized();

  std::string password_hash;
  password_hash.resize(crypto_pwhash_STRBYTES);
  if (crypto_pwhash_str_alg(password_hash.data(), password.data(),
                            password.size(), kArgonOpsLimit, kArgonMemLimit,
                            crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("failed to hash password");
  }

  password_hash.resize(std::char_traits<char>::length(password_hash.c_str()));
  return password_hash;
}

bool verify_password(std::string_view password,
                     const std::string &password_hash) {
  ensure_sodium_initialized();
  return crypto_pwhash_str_verify(password_hash.c_str(), password.data(),
                                  password.size()) == 0;
}

} // namespace roche_limit::auth_core
