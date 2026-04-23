#pragma once

#include <memory>

namespace roche_limit::auth_core {
class LoginService;
}

namespace roche_limit::auth_store {
class AuditRepository;
}

namespace roche_limit::server::http {

void register_login_routes(
    std::shared_ptr<const roche_limit::auth_core::LoginService> login_service,
    std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        audit_repository);

} // namespace roche_limit::server::http
