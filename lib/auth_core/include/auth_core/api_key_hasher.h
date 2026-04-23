#pragma once

#include <string>
#include <string_view>

namespace roche_limit::auth_core {

std::string hash_api_key(std::string_view api_key);
std::string api_key_lookup_hash(std::string_view api_key);
bool verify_api_key(std::string_view api_key, const std::string &api_key_hash);

} // namespace roche_limit::auth_core
