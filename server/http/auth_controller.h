#pragma once

#include <memory>

namespace roche_limit::auth_core {
class AuthService;
}

namespace roche_limit::server::http {

void register_auth_routes(std::shared_ptr<const roche_limit::auth_core::AuthService> auth_service);

}  // namespace roche_limit::server::http
