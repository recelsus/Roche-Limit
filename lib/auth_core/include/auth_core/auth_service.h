#pragma once

#include "auth_repository.h"
#include "auth_result.h"
#include "request_context.h"

namespace roche_limit::auth_core {

class AuthService {
public:
    explicit AuthService(const AuthRepository& repository);

    AuthResult authorize(const RequestContext& request_context) const;

private:
    const AuthRepository& repository_;
};

}  // namespace roche_limit::auth_core
