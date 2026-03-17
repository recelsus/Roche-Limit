#pragma once

#include <string>
#include <string_view>

namespace roche_limit::auth_core {

std::string hash_api_key(std::string_view api_key);

}  // namespace roche_limit::auth_core
