#include "auth_core/login_service.h"

#include "auth_core/ip_rule_matcher.h"
#include "auth_core/password_hasher.h"
#include "common/hash_util.h"

#include <sodium.h>

#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
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
    token.resize(sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING));
    sodium_bin2base64(token.data(),
                      token.size(),
                      bytes.data(),
                      bytes.size(),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    token.resize(std::char_traits<char>::length(token.c_str()));
    return token;
}

std::string session_token_hash(std::string_view session_token) {
    return roche_limit::common::sha256_hex(session_token);
}

bool is_ip_denied(const AuthRepository& auth_repository, std::string_view client_ip) {
    return select_most_specific_ip_match(client_ip, auth_repository.list_ip_rules(IpRuleEffect::Deny))
        .has_value();
}

struct IpAccessResult {
    int access_level;
    std::string reason;
};

IpAccessResult resolve_ip_access_level(const AuthRepository& auth_repository,
                                       std::string_view client_ip,
                                       std::string_view service_name) {
    const auto allow_match =
        select_most_specific_ip_match(client_ip, auth_repository.list_ip_rules(IpRuleEffect::Allow));
    if (!allow_match.has_value()) {
        return IpAccessResult{
            .access_level = 30,
            .reason = "unknown_ip",
        };
    }

    if (const auto service_level =
            auth_repository.find_ip_service_level(allow_match->id, service_name);
        service_level.has_value()) {
        return IpAccessResult{
            .access_level = service_level->access_level,
            .reason = "ip_service_override",
        };
    }

    return IpAccessResult{
        .access_level = 60,
        .reason = "ip_allow",
    };
}

}  // namespace

LoginService::LoginService(const AuthRepository& auth_repository,
                           const LoginRepository& login_repository)
    : auth_repository_(auth_repository), login_repository_(login_repository) {}

LoginResult LoginService::login(const LoginRequest& request) const {
    if (!is_valid_ip_address(request.client_ip)) {
        return LoginResult{
            .decision = LoginDecision::Deny,
            .reason = "invalid_client_ip",
        };
    }
    if (is_ip_denied(auth_repository_, request.client_ip)) {
        return LoginResult{
            .decision = LoginDecision::Deny,
            .reason = "ip_deny",
        };
    }

    const auto user = login_repository_.find_enabled_user_by_username(request.username);
    if (!user.has_value()) {
        return LoginResult{
            .decision = LoginDecision::Deny,
            .reason = "invalid_credentials",
        };
    }

    const auto credential = login_repository_.find_user_credential(user->id);
    if (!credential.has_value() || !verify_password(request.password, credential->password_hash)) {
        return LoginResult{
            .decision = LoginDecision::Deny,
            .reason = "invalid_credentials",
        };
    }

    const auto session_token = generate_session_token();
    const auto session_hash = session_token_hash(session_token);
    const auto expires_at =
        format_timestamp(std::chrono::system_clock::now() + std::chrono::hours(24 * kSessionPeriodDays));
    login_repository_.insert_user_session(user->id, session_hash, expires_at);

    return LoginResult{
        .decision = LoginDecision::Allow,
        .reason = "login_success",
        .user_id = user->id,
        .session_token = session_token,
        .expires_at = expires_at,
    };
}

SessionAuthResult LoginService::authorize_session(const SessionAuthRequest& request) const {
    if (!is_valid_ip_address(request.client_ip)) {
        return SessionAuthResult{
            .decision = LoginDecision::Deny,
            .access_level = 0,
            .reason = "invalid_client_ip",
        };
    }
    if (is_ip_denied(auth_repository_, request.client_ip)) {
        return SessionAuthResult{
            .decision = LoginDecision::Deny,
            .access_level = 0,
            .reason = "ip_deny",
        };
    }

    const auto ip_access = resolve_ip_access_level(auth_repository_, request.client_ip, request.service_name);
    const bool ip_satisfies_required_level =
        !request.required_access_level.has_value() || ip_access.access_level >= *request.required_access_level;
    if (ip_access.access_level > 0 && ip_satisfies_required_level) {
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
            .reason = "missing_session",
        };
    }

    const auto session =
        login_repository_.find_active_user_session(session_token_hash(*request.session_token));
    if (!session.has_value()) {
        return SessionAuthResult{
            .decision = LoginDecision::Deny,
            .access_level = 0,
            .reason = "invalid_session",
        };
    }

    const auto user = login_repository_.find_enabled_user_by_id(session->user_id);
    if (!user.has_value()) {
        return SessionAuthResult{
            .decision = LoginDecision::Deny,
            .access_level = 0,
            .reason = "invalid_session",
            .session_id = session->id,
        };
    }

    int access_level = 0;
    if (const auto service_level =
            login_repository_.find_user_service_level(user->id, request.service_name);
        service_level.has_value()) {
        access_level = service_level->access_level;
    }

    if (request.required_access_level.has_value() &&
        access_level < *request.required_access_level) {
        return SessionAuthResult{
            .decision = LoginDecision::Deny,
            .access_level = 0,
            .reason = "insufficient_level",
            .user_id = user->id,
            .session_id = session->id,
        };
    }

    login_repository_.update_user_session_last_seen(session->id);

    return SessionAuthResult{
        .decision = access_level > 0 ? LoginDecision::Allow : LoginDecision::Deny,
        .access_level = access_level > 0 ? access_level : 0,
        .reason = access_level > 0 ? "session_allow" : "insufficient_level",
        .user_id = user->id,
        .session_id = session->id,
    };
}

void LoginService::logout(std::string_view session_token) const {
    if (session_token.empty()) {
        return;
    }
    login_repository_.revoke_user_session(session_token_hash(session_token));
}

}  // namespace roche_limit::auth_core
