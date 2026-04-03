#pragma once

#include <filesystem>
#include <string>

namespace roche_limit::server::http {

std::string load_login_asset(std::string_view asset_name);

}  // namespace roche_limit::server::http
