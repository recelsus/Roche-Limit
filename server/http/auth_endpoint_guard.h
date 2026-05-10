#pragma once

#include <drogon/HttpTypes.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace drogon {
class HttpRequest;
using HttpRequestPtr = std::shared_ptr<HttpRequest>;
} // namespace drogon

namespace roche_limit::server::http {

struct AuthEndpointGuardConfig {
  bool rate_limit_enabled{true};
  int rate_limit_window_seconds{60};
  int auth_max_requests_per_window{600};
  int session_auth_max_requests_per_window{600};
  std::size_t max_header_bytes{8192};
  std::size_t max_query_bytes{1024};
  std::size_t max_body_bytes{0};
};

struct AuthEndpointGuardResult {
  bool allowed{true};
  drogon::HttpStatusCode status_code{drogon::k200OK};
  std::string reason;
  std::optional<int> retry_after_seconds;
};

AuthEndpointGuardConfig load_auth_endpoint_guard_config_from_env();
void initialize_auth_endpoint_guard_config(AuthEndpointGuardConfig config);
const AuthEndpointGuardConfig &auth_endpoint_guard_config();
void reset_auth_endpoint_rate_limits_for_tests();

bool is_valid_host_header(std::string_view host) noexcept;
bool is_valid_forwarded_proto_header(std::string_view proto) noexcept;

AuthEndpointGuardResult guard_auth_endpoint_request(
    const drogon::HttpRequestPtr &request, std::string_view endpoint_name,
    std::string_view peer_ip);

} // namespace roche_limit::server::http
