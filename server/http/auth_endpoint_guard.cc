#include "auth_endpoint_guard.h"

#include "auth_core/auth_reason.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <drogon/HttpRequest.h>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>

namespace roche_limit::server::http {

namespace {

AuthEndpointGuardConfig g_config;

struct RateBucket {
  std::chrono::steady_clock::time_point window_started_at;
  int count{0};
};

std::mutex g_rate_limit_mutex;
std::unordered_map<std::string, RateBucket> g_rate_limit_buckets;

int env_int_or_default(const char *name, int fallback) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }

  const std::string_view text(value);
  int parsed = 0;
  const auto *begin = text.data();
  const auto *end = begin + text.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end || parsed < 0) {
    return fallback;
  }
  return parsed;
}

std::size_t env_size_or_default(const char *name, std::size_t fallback) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }

  const std::string_view text(value);
  std::size_t parsed = 0;
  const auto *begin = text.data();
  const auto *end = begin + text.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end) {
    return fallback;
  }
  return parsed;
}

bool env_flag_or_default(const char *name, bool fallback) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }
  const std::string_view text(value);
  if (text == "1" || text == "true" || text == "yes") {
    return true;
  }
  if (text == "0" || text == "false" || text == "no") {
    return false;
  }
  return fallback;
}

bool public_like_deployment_mode() {
  const char *value = std::getenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  if (value == nullptr || *value == '\0') {
    return false;
  }
  const std::string_view mode(value);
  return mode == "public" || mode == "hardened";
}

std::size_t header_bytes(const drogon::HttpRequestPtr &request) {
  std::size_t total = 0;
  for (const auto &[name, value] : request->headers()) {
    total += name.size() + value.size() + 4;
  }
  return total;
}

AuthEndpointGuardResult deny(drogon::HttpStatusCode status_code,
                             std::string_view reason,
                             std::optional<int> retry_after = std::nullopt) {
  return AuthEndpointGuardResult{
      .allowed = false,
      .status_code = status_code,
      .reason = std::string(reason),
      .retry_after_seconds = retry_after,
  };
}

int endpoint_limit(const AuthEndpointGuardConfig &config,
                   std::string_view endpoint_name) {
  if (endpoint_name == "session_auth") {
    return config.session_auth_max_requests_per_window;
  }
  if (endpoint_name == "login" || endpoint_name == "login_page") {
    return config.login_max_requests_per_window;
  }
  if (endpoint_name == "logout") {
    return config.logout_max_requests_per_window;
  }
  return config.auth_max_requests_per_window;
}

AuthEndpointGuardResult check_rate_limit(std::string_view endpoint_name,
                                         std::string_view peer_ip,
                                         std::optional<int> limit_override =
                                             std::nullopt) {
  const auto &config = auth_endpoint_guard_config();
  if (!config.rate_limit_enabled) {
    return AuthEndpointGuardResult{};
  }
  const int limit =
      limit_override.has_value() ? *limit_override : endpoint_limit(config, endpoint_name);
  if (limit <= 0) {
    return AuthEndpointGuardResult{};
  }

  const auto now = std::chrono::steady_clock::now();
  const auto window = std::chrono::seconds(config.rate_limit_window_seconds);
  const std::string key =
      std::string(endpoint_name) + "|" + std::string(peer_ip);

  std::lock_guard lock(g_rate_limit_mutex);
  auto &bucket = g_rate_limit_buckets[key];
  if (bucket.count == 0 || now - bucket.window_started_at >= window) {
    bucket.window_started_at = now;
    bucket.count = 1;
    return AuthEndpointGuardResult{};
  }
  if (bucket.count >= limit) {
    const auto retry_after = std::max<int>(
        1, static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
                                window - (now - bucket.window_started_at))
                                .count()));
    return deny(drogon::k429TooManyRequests,
                roche_limit::auth_core::auth_reason::RateLimited,
                retry_after);
  }
  ++bucket.count;
  return AuthEndpointGuardResult{};
}

} // namespace

AuthEndpointGuardConfig load_auth_endpoint_guard_config_from_env() {
  return AuthEndpointGuardConfig{
      .rate_limit_enabled =
          env_flag_or_default("ROCHE_LIMIT_AUTH_RATE_LIMIT_ENABLED", true),
      .rate_limit_window_seconds =
          env_int_or_default("ROCHE_LIMIT_AUTH_RATE_LIMIT_WINDOW_SECONDS", 60),
      .auth_max_requests_per_window =
          env_int_or_default("ROCHE_LIMIT_AUTH_RATE_LIMIT_PER_WINDOW", 600),
      .session_auth_max_requests_per_window = env_int_or_default(
          "ROCHE_LIMIT_SESSION_AUTH_RATE_LIMIT_PER_WINDOW", 600),
      .login_max_requests_per_window =
          env_int_or_default("ROCHE_LIMIT_LOGIN_RATE_LIMIT_PER_WINDOW", 120),
      .logout_max_requests_per_window =
          env_int_or_default("ROCHE_LIMIT_LOGOUT_RATE_LIMIT_PER_WINDOW", 120),
      .max_header_bytes =
          env_size_or_default("ROCHE_LIMIT_AUTH_MAX_HEADER_BYTES", 8192),
      .max_query_bytes =
          env_size_or_default("ROCHE_LIMIT_AUTH_MAX_QUERY_BYTES", 1024),
      .max_body_bytes =
          env_size_or_default("ROCHE_LIMIT_AUTH_MAX_BODY_BYTES", 0),
      .login_max_body_bytes =
          env_size_or_default("ROCHE_LIMIT_LOGIN_MAX_BODY_BYTES", 16384),
      .logout_max_body_bytes =
          env_size_or_default("ROCHE_LIMIT_LOGOUT_MAX_BODY_BYTES", 4096),
  };
}

void initialize_auth_endpoint_guard_config(AuthEndpointGuardConfig config) {
  if (config.rate_limit_window_seconds <= 0) {
    config.rate_limit_window_seconds = 60;
  }
  g_config = config;
}

const AuthEndpointGuardConfig &auth_endpoint_guard_config() {
  return g_config;
}

void reset_auth_endpoint_rate_limits_for_tests() {
  std::lock_guard lock(g_rate_limit_mutex);
  g_rate_limit_buckets.clear();
}

bool is_valid_host_header(std::string_view host) noexcept {
  if (host.empty()) {
    return true;
  }
  if (host.size() > 253 || host.find(',') != std::string_view::npos) {
    return false;
  }
  for (const unsigned char ch : host) {
    if (std::iscntrl(ch) || std::isspace(ch) || ch == '/' || ch == '\\' ||
        ch == '@') {
      return false;
    }
  }
  return true;
}

bool is_valid_forwarded_proto_header(std::string_view proto) noexcept {
  if (proto.empty()) {
    return true;
  }
  return proto == "http" || proto == "https";
}

AuthEndpointGuardResult guard_auth_endpoint_request(
    const drogon::HttpRequestPtr &request, std::string_view endpoint_name,
    std::string_view peer_ip) {
  const auto &config = auth_endpoint_guard_config();
  return guard_endpoint_request(
      request, endpoint_name, peer_ip,
      EndpointGuardOptions{
          .allowed_method = drogon::Get,
          .max_body_bytes = config.max_body_bytes,
          .max_requests_per_window = endpoint_limit(config, endpoint_name),
      });
}

AuthEndpointGuardResult guard_endpoint_request(
    const drogon::HttpRequestPtr &request, std::string_view endpoint_name,
    std::string_view peer_ip, EndpointGuardOptions options) {
  if (request->method() != options.allowed_method || request->isHead()) {
    return deny(drogon::k405MethodNotAllowed,
                roche_limit::auth_core::auth_reason::InvalidHeader);
  }

  const auto &config = auth_endpoint_guard_config();
  if (config.max_header_bytes > 0 && header_bytes(request) > config.max_header_bytes) {
    return deny(drogon::k431RequestHeaderFieldsTooLarge,
                roche_limit::auth_core::auth_reason::InvalidHeader);
  }
  if (config.max_query_bytes > 0 &&
      request->query().size() > config.max_query_bytes) {
    return deny(drogon::k414RequestURITooLarge,
                roche_limit::auth_core::auth_reason::InvalidHeader);
  }
  if (request->bodyLength() > options.max_body_bytes ||
      request->realContentLength() > options.max_body_bytes) {
    return deny(drogon::k413RequestEntityTooLarge,
                roche_limit::auth_core::auth_reason::InvalidHeader);
  }
  if (!is_valid_host_header(request->getHeader("Host"))) {
    return deny(drogon::k400BadRequest,
                roche_limit::auth_core::auth_reason::InvalidHeader);
  }
  if (!is_valid_forwarded_proto_header(request->getHeader("X-Forwarded-Proto"))) {
    return deny(drogon::k400BadRequest,
                roche_limit::auth_core::auth_reason::InvalidHeader);
  }
  if (public_like_deployment_mode() &&
      request->getHeader("X-Forwarded-Proto") == "http") {
    return deny(drogon::k400BadRequest,
                roche_limit::auth_core::auth_reason::InvalidHeader);
  }

  return check_rate_limit(endpoint_name, peer_ip,
                          options.max_requests_per_window);
}

} // namespace roche_limit::server::http
