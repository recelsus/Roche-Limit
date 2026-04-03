#pragma once

#include <memory>

namespace roche_limit::auth_core {
class LoginService;
}

namespace roche_limit::server::http {

void register_login_routes(std::shared_ptr<const roche_limit::auth_core::LoginService> login_service);

}  // namespace roche_limit::server::http
