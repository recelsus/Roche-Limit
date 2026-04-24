#pragma once

#include "auth_core/login_request.h"
#include "auth_core/request_context.h"

#include <drogon/HttpRequest.h>
#include <string_view>

namespace roche_limit::server::http {

struct ParsedRequiredAccessLevel {
    std::optional<int> value;
    bool present{false};
    bool valid{true};
};

ParsedRequiredAccessLevel parse_required_access_level_header(std::string_view header_value);
std::string resolve_request_client_ip(const drogon::HttpRequestPtr& request);

roche_limit::auth_core::RequestContext build_request_context(
    const drogon::HttpRequestPtr& request);
roche_limit::auth_core::LoginRequest build_login_request(
    const drogon::HttpRequestPtr& request);
roche_limit::auth_core::SessionAuthRequest build_session_auth_request(
    const drogon::HttpRequestPtr& request);

}  // namespace roche_limit::server::http
