#pragma once

#include <optional>
#include <string>

namespace roche_limit::auth_core {

struct LoginRequest {
    std::string client_ip;
    std::string username;
    std::string password;
};

struct SessionAuthRequest {
    std::string client_ip;
    std::string service_name;
    std::optional<int> required_access_level;
    bool required_access_level_present{false};
    bool required_access_level_valid{true};
    std::optional<std::string> session_token;
};

}  // namespace roche_limit::auth_core
