#include "auth_core/login_service.h"

#include "auth_core/access_level.h"
#include "auth_core/auth_reason.h"
#include "auth_core/ip_rule_matcher.h"
#include "auth_core/password_hasher.h"
#include "common/debug_log.h"
#include "common/hash_util.h"

#include <sodium.h>

#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace roche_limit::auth_core {

namespace {

constexpr int kSessionPeriodDays = 7;
// constexpr int kSessionPeriodDays = 30;

std::string format_timestamp(std::chrono::system_clock::time_point time_point) {
  const auto time = std::chrono::system_clock::to_time_t(time_point);
  std::tm utc_time{};
#if defined(_WIN32)
  gmtime_s(&utc_time, &time);
#else
  gmtime_r(&time, &utc_time);
#endif
  std::ostringstream stream;
  stream << std::put_time(&utc_time, "%Y-%m-%d %H:%M:%S");
  return stream.str();
}

std::string generate_session_token() {
  if (sodium_init() < 0) {
    throw std::runtime_error("failed to initialize libsodium");
  }

  std::array<unsigned char, 24> bytes{};
  randombytes_buf(bytes.data(), bytes.size());

  std::string token;
  token.resize(sodium_base64_encoded_len(
      bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING));
  sodium_bin2base64(token.data(), token.size(), bytes.data(), bytes.size(),
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  token.resize(std::char_traits<char>::length(token.c_str()));
  return token;
}

std::string session_token_hash(std::string_view session_token) {
  return roche_limit::common::sha256_hex(session_token);
}

bool session_is_expired(std::string_view expires_at) {
  return expires_at.empty() ||
         expires_at <= format_timestamp(std::chrono::system_clock::now());
}

bool is_ip_denied(const AuthRepository &auth_repository,
                  std::string_view client_ip) {
  return select_most_specific_ip_match(
             client_ip, auth_repository.list_ip_rules(IpRuleEffect::Deny))
      .has_value();
}

struct IpAccessResult {
  int access_level;
  std::string reason;
};

IpAccessResult resolve_ip_access_level(const AuthRepository &auth_repository,
                                       std::string_view client_ip,
                                       std::string_view service_name) {
  const auto allow_match = select_most_specific_ip_match(
      client_ip, auth_repository.list_ip_rules(IpRuleEffect::Allow));
  if (!allow_match.has_value()) {
    return IpAccessResult{
        .access_level = unknown_ip_access_level(),
        .reason = auth_reason::UnknownIp,
    };
  }

  if (const auto service_level =
          auth_repository.find_ip_service_level(allow_match->id, service_name);
      service_level.has_value()) {
    return IpAccessResult{
        .access_level = service_level->access_level,
        .reason = auth_reason::IpServiceOverride,
    };
  }

  return IpAccessResult{
      .access_level = 60,
      .reason = auth_reason::IpAllow,
  };
}

} // namespace

LoginService::LoginService(
    std::shared_ptr<const AuthRepository> auth_repository,
    std::shared_ptr<const LoginRepository> login_repository)
    : auth_repository_(std::move(auth_repository)),
      login_repository_(std::move(login_repository)) {
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[login_core] LoginService constructed this="
              << static_cast<const void *>(this) << " auth_repository="
              << static_cast<const void *>(auth_repository_.get())
              << " login_repository="
              << static_cast<const void *>(login_repository_.get())
              << std::endl;
  }
}

LoginResult LoginService::login(const LoginRequest &request) const {
  if (!is_valid_ip_address(request.client_ip)) {
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = auth_reason::InvalidClientIp,
    };
  }
  if (is_ip_denied(*auth_repository_, request.client_ip)) {
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = auth_reason::IpDeny,
    };
  }

  const auto user =
      login_repository_->find_enabled_user_by_username(request.username);
  if (!user.has_value()) {
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = auth_reason::InvalidCredentials,
    };
  }

  const auto credential = login_repository_->find_user_credential(user->id);
  if (!credential.has_value() ||
      !verify_password(request.password, credential->password_hash)) {
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = auth_reason::InvalidCredentials,
    };
  }

  const auto session_token = generate_session_token();
  const auto session_hash = session_token_hash(session_token);
  const auto expires_at =
      format_timestamp(std::chrono::system_clock::now() +
                       std::chrono::hours(24 * kSessionPeriodDays));
  login_repository_->insert_user_session(user->id, session_hash, expires_at);

  return LoginResult{
      .decision = LoginDecision::Allow,
      .reason = auth_reason::LoginSuccess,
      .user_id = user->id,
      .session_token = session_token,
      .expires_at = expires_at,
  };
}

SessionAuthResult
LoginService::authorize_session(const SessionAuthRequest &request) const {
  if (!is_valid_ip_address(request.client_ip)) {
    return SessionAuthResult{
        .decision = LoginDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::InvalidClientIp,
    };
  }
  if (is_ip_denied(*auth_repository_, request.client_ip)) {
    return SessionAuthResult{
        .decision = LoginDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::IpDeny,
    };
  }

  const auto ip_access = resolve_ip_access_level(
      *auth_repository_, request.client_ip, request.service_name);
  if (access_level_satisfies(ip_access.access_level,
                             request.required_access_level)) {
    return SessionAuthResult{
        .decision = LoginDecision::Allow,
        .access_level = ip_access.access_level,
        .reason = ip_access.reason,
    };
  }

  if (!request.session_token.has_value() || request.session_token->empty()) {
    return SessionAuthResult{
        .decision = LoginDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::MissingSession,
    };
  }

  const auto session = login_repository_->find_active_user_session(
      session_token_hash(*request.session_token));
  if (!session.has_value()) {
    return SessionAuthResult{
        .decision = LoginDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::InvalidSession,
    };
  }
  if (session_is_expired(session->expires_at)) {
    login_repository_->revoke_user_session(session->session_token_hash);
    return SessionAuthResult{
        .decision = LoginDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::ExpiredSession,
        .session_id = session->id,
    };
  }

  const auto user =
      login_repository_->find_enabled_user_by_id(session->user_id);
  if (!user.has_value()) {
    return SessionAuthResult{
        .decision = LoginDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::InvalidSession,
        .session_id = session->id,
    };
  }

  int access_level = 0;
  if (const auto service_level = login_repository_->find_user_service_level(
          user->id, request.service_name);
      service_level.has_value()) {
    access_level = service_level->access_level;
  }

  if (!access_level_satisfies(access_level, request.required_access_level)) {
    return SessionAuthResult{
        .decision = LoginDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::InsufficientLevel,
        .user_id = user->id,
        .session_id = session->id,
    };
  }

  login_repository_->update_user_session_last_seen(session->id);

  const bool session_level_allowed =
      access_level_satisfies(access_level, std::nullopt);
  return SessionAuthResult{
      .decision =
          session_level_allowed ? LoginDecision::Allow : LoginDecision::Deny,
      .access_level = session_level_allowed ? access_level : 0,
      .reason = session_level_allowed ? auth_reason::SessionAllow
                                      : auth_reason::InsufficientLevel,
      .user_id = user->id,
      .session_id = session->id,
  };
}

void LoginService::logout(std::string_view session_token) const {
  if (session_token.empty()) {
    return;
  }
  login_repository_->revoke_user_session(session_token_hash(session_token));
}

} // namespace roche_limit::auth_core
