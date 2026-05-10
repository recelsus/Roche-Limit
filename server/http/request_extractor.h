#pragma once

#include "auth_core/login_request.h"
#include "auth_core/request_context.h"

#include <memory>
#include <string_view>

namespace drogon {
class HttpRequest;
using HttpRequestPtr = std::shared_ptr<HttpRequest>;
}

namespace roche_limit::server::http {

struct ParsedRequiredAccessLevel {
    std::optional<int> value;
    bool present{false};
    bool valid{true};
};

bool is_valid_target_service_name(std::string_view service_name) noexcept;
bool has_multiple_single_value_header_values(std::string_view header_value) noexcept;
bool forwarded_client_ip_headers_conflict(std::string_view real_ip_header,
                                          std::string_view forwarded_for_header);
ParsedRequiredAccessLevel parse_required_access_level_header(std::string_view header_value);
std::string resolve_request_client_ip(const drogon::HttpRequestPtr& request);

roche_limit::auth_core::RequestContext build_request_context(
    const drogon::HttpRequestPtr& request);
roche_limit::auth_core::LoginRequest build_login_request(
    const drogon::HttpRequestPtr& request);
roche_limit::auth_core::SessionAuthRequest build_session_auth_request(
    const drogon::HttpRequestPtr& request);

}  // namespace roche_limit::server::http
