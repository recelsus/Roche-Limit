#pragma once

#include "auth_repository.h"
#include "login_repository.h"
#include "login_request.h"
#include "login_result.h"

#include <memory>
#include <string>

namespace roche_limit::auth_core {

class LoginService {
public:
  LoginService(std::shared_ptr<const AuthRepository> auth_repository,
               std::shared_ptr<const LoginRepository> login_repository);

  LoginResult login(const LoginRequest &request) const;
  SessionAuthResult authorize_session(const SessionAuthRequest &request) const;
  void logout(std::string_view session_token) const;

private:
  std::shared_ptr<const AuthRepository> auth_repository_;
  std::shared_ptr<const LoginRepository> login_repository_;
};

} // namespace roche_limit::auth_core
