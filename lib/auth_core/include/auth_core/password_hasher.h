#pragma once

#include <string>
#include <string_view>

namespace roche_limit::auth_core {

std::string hash_password(std::string_view password);
bool verify_password(std::string_view password, std::string_view password_hash);

}  // namespace roche_limit::auth_core
