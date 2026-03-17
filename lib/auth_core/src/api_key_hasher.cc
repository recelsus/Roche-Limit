#include "auth_core/api_key_hasher.h"

#include "common/hash_util.h"

namespace roche_limit::auth_core {

std::string hash_api_key(std::string_view api_key) {
    return roche_limit::common::sha256_hex(api_key);
}

}  // namespace roche_limit::auth_core
