#pragma once

#include <optional>
#include <string>

namespace roche_limit::auth_core {

struct RequestContext {
    std::string client_ip;
    std::string service_name;
    std::optional<std::string> api_key;
};

}  // namespace roche_limit::auth_core
