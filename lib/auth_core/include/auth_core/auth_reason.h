#pragma once

namespace roche_limit::auth_core::auth_reason {

inline constexpr auto ApiKeyElevated = "api_key_elevated";
inline constexpr auto ExpiredSession = "expired_session";
inline constexpr auto InternalError = "internal_error";
inline constexpr auto InvalidClientIp = "invalid_client_ip";
inline constexpr auto InvalidCredentials = "invalid_credentials";
inline constexpr auto InvalidSession = "invalid_session";
inline constexpr auto IpAllow = "ip_allow";
inline constexpr auto IpDeny = "ip_deny";
inline constexpr auto IpServiceOverride = "ip_service_override";
inline constexpr auto LoginSuccess = "login_success";
inline constexpr auto Logout = "logout";
inline constexpr auto MissingService = "missing_service";
inline constexpr auto MissingSession = "missing_session";
inline constexpr auto SessionAllow = "session_allow";
inline constexpr auto UnknownIp = "unknown_ip";
inline constexpr auto InsufficientLevel = "insufficient_level";

}  // namespace roche_limit::auth_core::auth_reason
