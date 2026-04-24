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
#include <optional>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace roche_limit::auth_core {

namespace {

constexpr int kSessionPeriodDays = 7;
constexpr int kCsrfTokenTtlMinutes = 10;
constexpr int kLoginLockoutThreshold = 8;
constexpr int kLoginLockoutSeconds = 900;
constexpr int kMaxBackoffSeconds = 300;
constexpr std::string_view kCsrfPurposeLogin = "login";
constexpr std::string_view kCsrfPurposeLogout = "logout";

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

std::optional<std::chrono::system_clock::time_point>
parse_timestamp(std::string_view text) {
  if (text.empty()) {
    return std::nullopt;
  }

  std::tm utc_time{};
  std::istringstream stream{std::string(text)};
  stream >> std::get_time(&utc_time, "%Y-%m-%d %H:%M:%S");
  if (stream.fail()) {
    return std::nullopt;
  }
#if defined(_WIN32)
  return std::chrono::system_clock::from_time_t(_mkgmtime(&utc_time));
#else
  return std::chrono::system_clock::from_time_t(timegm(&utc_time));
#endif
}

std::string generate_random_token(std::size_t size) {
  if (sodium_init() < 0) {
    throw std::runtime_error("failed to initialize libsodium");
  }

  std::vector<unsigned char> bytes(size);
  randombytes_buf(bytes.data(), bytes.size());

  std::string token;
  token.resize(sodium_base64_encoded_len(
      bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING));
  sodium_bin2base64(token.data(), token.size(), bytes.data(), bytes.size(),
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  token.resize(std::char_traits<char>::length(token.c_str()));
  return token;
}

std::string generate_session_token() { return generate_random_token(24); }

std::string generate_csrf_token() { return generate_random_token(24); }

std::string session_token_hash(std::string_view session_token) {
  return roche_limit::common::sha256_hex(session_token);
}

std::string csrf_token_hash(std::string_view csrf_token) {
  return roche_limit::common::sha256_hex(csrf_token);
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

int lockout_retry_after_seconds(
    const std::optional<LoginFailureRecord> &failure_record,
    std::chrono::system_clock::time_point now) {
  if (!failure_record.has_value() || !failure_record->locked_until.has_value()) {
    return 0;
  }
  const auto locked_until = parse_timestamp(*failure_record->locked_until);
  if (!locked_until.has_value() || *locked_until <= now) {
    return 0;
  }
  const auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(*locked_until - now)
          .count();
  return static_cast<int>(std::min<long long>(
      seconds, std::numeric_limits<int>::max()));
}

int backoff_delay_seconds(int failure_count) {
  if (failure_count <= 0) {
    return 0;
  }
  const auto shift = std::min(failure_count - 1, 8);
  const auto delay = 1 << shift;
  return std::min(delay, kMaxBackoffSeconds);
}

int login_retry_after_seconds(
    const std::optional<LoginFailureRecord> &failure_record,
    std::chrono::system_clock::time_point now) {
  const auto locked_seconds = lockout_retry_after_seconds(failure_record, now);
  if (locked_seconds > 0) {
    return locked_seconds;
  }
  if (!failure_record.has_value() || failure_record->failure_count <= 0) {
    return 0;
  }
  const auto last_failed_at = parse_timestamp(failure_record->last_failed_at);
  if (!last_failed_at.has_value()) {
    return 0;
  }
  const auto allowed_at =
      *last_failed_at +
      std::chrono::seconds(backoff_delay_seconds(failure_record->failure_count));
  if (allowed_at <= now) {
    return 0;
  }
  const auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(allowed_at - now)
          .count();
  return static_cast<int>(std::min<long long>(
      seconds, std::numeric_limits<int>::max()));
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

bool LoginService::can_access_login_page(std::string_view client_ip) const {
  return is_valid_ip_address(client_ip) &&
         !is_ip_denied(*auth_repository_, client_ip);
}

std::string LoginService::issue_csrf_token(std::string_view purpose,
                                           std::string_view client_ip) const {
  const auto token = generate_csrf_token();
  login_repository_->insert_csrf_token(
      purpose, csrf_token_hash(token), client_ip,
      format_timestamp(std::chrono::system_clock::now() +
                       std::chrono::minutes(kCsrfTokenTtlMinutes)));
  return token;
}

bool LoginService::validate_csrf_token(
    std::string_view purpose, std::string_view client_ip,
    std::optional<std::string_view> csrf_token,
    std::optional<std::string_view> csrf_cookie_token) const {
  if (!csrf_token.has_value() || csrf_token->empty() ||
      !csrf_cookie_token.has_value() || csrf_cookie_token->empty()) {
    return false;
  }
  if (*csrf_token != *csrf_cookie_token) {
    return false;
  }
  return login_repository_->has_valid_csrf_token(
      purpose, csrf_token_hash(*csrf_token), client_ip);
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
  if (!validate_csrf_token(kCsrfPurposeLogin, request.client_ip,
                           request.csrf_token,
                           request.csrf_cookie_token)) {
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = auth_reason::InvalidCsrf,
    };
  }

  const auto now = std::chrono::system_clock::now();
  const auto failure_record = login_repository_->find_login_failure(
      request.client_ip, request.username);
  const auto locked_retry_after = lockout_retry_after_seconds(failure_record, now);
  if (locked_retry_after > 0) {
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = auth_reason::Locked,
        .retry_after_seconds = locked_retry_after,
    };
  }
  const auto retry_after = login_retry_after_seconds(failure_record, now);
  if (retry_after > 0) {
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = auth_reason::RateLimited,
        .retry_after_seconds = retry_after,
    };
  }

  const auto user =
      login_repository_->find_enabled_user_by_username(request.username);
  if (!user.has_value()) {
    const int next_failure_count =
        failure_record.has_value() ? failure_record->failure_count + 1 : 1;
    const bool should_lock = next_failure_count >= kLoginLockoutThreshold;
    const auto locked_until = should_lock
                                  ? std::optional<std::string>(format_timestamp(
                                        now + std::chrono::seconds(
                                                  kLoginLockoutSeconds)))
                                  : std::nullopt;
    login_repository_->upsert_login_failure(
        request.client_ip, request.username, next_failure_count,
        locked_until.has_value()
            ? std::optional<std::string_view>(*locked_until)
            : std::nullopt);
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = should_lock ? auth_reason::Locked
                              : auth_reason::InvalidCredentials,
        .retry_after_seconds =
            should_lock ? std::optional<int>(kLoginLockoutSeconds) : std::nullopt,
    };
  }

  const auto credential = login_repository_->find_user_credential(user->id);
  if (!credential.has_value() ||
      !verify_password(request.password, credential->password_hash)) {
    const int next_failure_count =
        failure_record.has_value() ? failure_record->failure_count + 1 : 1;
    const bool should_lock = next_failure_count >= kLoginLockoutThreshold;
    const auto locked_until = should_lock
                                  ? std::optional<std::string>(format_timestamp(
                                        now + std::chrono::seconds(
                                                  kLoginLockoutSeconds)))
                                  : std::nullopt;
    login_repository_->upsert_login_failure(
        request.client_ip, request.username, next_failure_count,
        locked_until.has_value()
            ? std::optional<std::string_view>(*locked_until)
            : std::nullopt);
    return LoginResult{
        .decision = LoginDecision::Deny,
        .reason = should_lock ? auth_reason::Locked
                              : auth_reason::InvalidCredentials,
        .retry_after_seconds =
            should_lock ? std::optional<int>(kLoginLockoutSeconds) : std::nullopt,
    };
  }

  login_repository_->clear_login_failure(request.client_ip, request.username);
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
