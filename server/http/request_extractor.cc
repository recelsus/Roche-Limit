#include "request_extractor.h"
#include "client_ip_resolver.h"
#include "session_cookie_config.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <drogon/drogon.h>

namespace roche_limit::server::http {

namespace {

bool starts_with_bearer_token(std::string_view value) {
    constexpr std::string_view kBearerPrefix = "Bearer ";
    if (value.size() < kBearerPrefix.size()) {
        return false;
    }

    for (std::size_t index = 0; index < kBearerPrefix.size(); ++index) {
        if (std::tolower(static_cast<unsigned char>(value[index])) !=
            std::tolower(static_cast<unsigned char>(kBearerPrefix[index]))) {
            return false;
        }
    }
    return true;
}

std::string trim(std::string value) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

std::string extract_client_ip(const drogon::HttpRequestPtr& request) {
    static std::atomic_bool warned_untrusted_forwarded_headers{false};
    bool expected = false;
    if (trusted_proxy_rules().empty() &&
        (!request->getHeader("X-Real-IP").empty() || !request->getHeader("X-Forwarded-For").empty())) {
        if (warned_untrusted_forwarded_headers.compare_exchange_strong(expected, true)) {
            LOG_WARN << "forwarded client IP headers ignored because ROCHE_LIMIT_TRUSTED_PROXIES is unset";
        }
    }
    return resolve_client_ip(request->peerAddr().toIp(),
                             request->getHeader("X-Real-IP"),
                             request->getHeader("X-Forwarded-For"),
                             trusted_proxy_rules());
}

std::optional<std::string> extract_api_key(const drogon::HttpRequestPtr& request) {
    const auto authorization = request->getHeader("Authorization");
    if (starts_with_bearer_token(authorization)) {
        return authorization.substr(std::string_view("Bearer ").size());
    }

    const auto explicit_api_key = request->getHeader("X-API-Key");
    if (!explicit_api_key.empty()) {
        return explicit_api_key;
    }

    const auto legacy_api_key = request->getHeader("X-Api-Key");
    if (!legacy_api_key.empty()) {
        return legacy_api_key;
    }

    return std::nullopt;
}

}  // namespace

ParsedRequiredAccessLevel parse_required_access_level_header(std::string_view raw_header_value) {
    const auto header_value = trim(std::string(raw_header_value));
    if (header_value.empty()) {
        return ParsedRequiredAccessLevel{
            .value = std::nullopt,
            .present = false,
            .valid = true,
        };
    }

    int parsed_level = 0;
    const auto* begin = header_value.data();
    const auto* end = begin + header_value.size();
    const auto result = std::from_chars(begin, end, parsed_level);
    if (result.ec != std::errc{} || result.ptr != end || parsed_level < 0) {
        return ParsedRequiredAccessLevel{
            .value = std::nullopt,
            .present = true,
            .valid = false,
        };
    }

    return ParsedRequiredAccessLevel{
        .value = parsed_level,
        .present = true,
        .valid = true,
    };
}

std::string resolve_request_client_ip(const drogon::HttpRequestPtr& request) {
    return extract_client_ip(request);
}

roche_limit::auth_core::RequestContext build_request_context(
    const drogon::HttpRequestPtr& request) {
    const auto parsed_required_level =
        parse_required_access_level_header(request->getHeader("X-Required-Level"));
    return roche_limit::auth_core::RequestContext{
        .client_ip = extract_client_ip(request),
        .service_name = trim(request->getHeader("X-Target-Service")),
        .api_key = extract_api_key(request),
        .required_access_level = parsed_required_level.value,
        .required_access_level_present = parsed_required_level.present,
        .required_access_level_valid = parsed_required_level.valid,
    };
}

roche_limit::auth_core::LoginRequest build_login_request(
    const drogon::HttpRequestPtr& request) {
    const auto& cookie_config = session_cookie_config();
    return roche_limit::auth_core::LoginRequest{
        .client_ip = extract_client_ip(request),
        .username = request->getParameter("username"),
        .password = request->getParameter("password"),
        .csrf_token = request->getParameter("csrf_token").empty()
                          ? std::nullopt
                          : std::optional<std::string>(
                                request->getParameter("csrf_token")),
        .csrf_cookie_token =
            request->getCookie(csrf_cookie_name(cookie_config)).empty()
                ? std::nullopt
                : std::optional<std::string>(
                      request->getCookie(csrf_cookie_name(cookie_config))),
    };
}

roche_limit::auth_core::SessionAuthRequest build_session_auth_request(
    const drogon::HttpRequestPtr& request) {
    const auto parsed_required_level =
        parse_required_access_level_header(request->getHeader("X-Required-Level"));
    const auto session_cookie = request->getCookie(session_cookie_config().name);
    return roche_limit::auth_core::SessionAuthRequest{
        .client_ip = extract_client_ip(request),
        .service_name = trim(request->getHeader("X-Target-Service")),
        .required_access_level = parsed_required_level.value,
        .required_access_level_present = parsed_required_level.present,
        .required_access_level_valid = parsed_required_level.valid,
        .session_token = session_cookie.empty() ? std::nullopt
                                                : std::optional<std::string>(session_cookie),
    };
}

}  // namespace roche_limit::server::http
