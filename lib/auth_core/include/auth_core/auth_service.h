#pragma once

#include "auth_repository.h"
#include "auth_result.h"
#include "request_context.h"

namespace roche_limit::auth_core {

class AuthService {
public:
    explicit AuthService(const AuthRepository& repository);

    AuthResult authorize(const RequestContext& request_context) const;
    const AuthRepository* repository_address() const noexcept;

private:
    const AuthRepository& repository_;
};

}  // namespace roche_limit::auth_core
