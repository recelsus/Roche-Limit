#pragma once

#include <optional>
#include <string>

namespace roche_limit::auth_core {

struct RequestContext {
    std::string client_ip;
    std::string service_name;
    std::optional<std::string> api_key;
    std::optional<int> required_access_level;
    bool required_access_level_present{false};
    bool required_access_level_valid{true};
};

}  // namespace roche_limit::auth_core
