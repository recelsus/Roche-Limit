#include "request_extractor.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string>

namespace roche_limit::server::http {

namespace {

constexpr std::string_view kSessionCookieName = "roche_limit_session";

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

std::string extract_forwarded_ip(const drogon::HttpRequestPtr& request) {
    const auto forwarded_for = request->getHeader("X-Forwarded-For");
    if (forwarded_for.empty()) {
        return {};
    }

    const auto separator = forwarded_for.find(',');
    return trim(forwarded_for.substr(0, separator));
}

std::string extract_client_ip(const drogon::HttpRequestPtr& request) {
    auto client_ip = trim(request->getHeader("X-Real-IP"));
    if (client_ip.empty()) {
        client_ip = extract_forwarded_ip(request);
    }
    if (client_ip.empty()) {
        client_ip = request->peerAddr().toIp();
    }
    return client_ip;
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

std::optional<int> extract_required_access_level(const drogon::HttpRequestPtr& request) {
    const auto header_value = trim(request->getHeader("X-Required-Level"));
    if (header_value.empty()) {
        return std::nullopt;
    }

    int parsed_level = 0;
    const auto* begin = header_value.data();
    const auto* end = begin + header_value.size();
    const auto result = std::from_chars(begin, end, parsed_level);
    if (result.ec != std::errc{} || result.ptr != end || parsed_level < 0) {
        return std::nullopt;
    }

    return parsed_level;
}

}  // namespace

roche_limit::auth_core::RequestContext build_request_context(
    const drogon::HttpRequestPtr& request) {
    return roche_limit::auth_core::RequestContext{
        .client_ip = extract_client_ip(request),
        .service_name = trim(request->getHeader("X-Target-Service")),
        .api_key = extract_api_key(request),
        .required_access_level = extract_required_access_level(request),
    };
}

roche_limit::auth_core::LoginRequest build_login_request(
    const drogon::HttpRequestPtr& request) {
    return roche_limit::auth_core::LoginRequest{
        .client_ip = extract_client_ip(request),
        .username = request->getParameter("username"),
        .password = request->getParameter("password"),
    };
}

roche_limit::auth_core::SessionAuthRequest build_session_auth_request(
    const drogon::HttpRequestPtr& request) {
    const auto session_cookie = request->getCookie(std::string(kSessionCookieName));
    return roche_limit::auth_core::SessionAuthRequest{
        .client_ip = extract_client_ip(request),
        .service_name = trim(request->getHeader("X-Target-Service")),
        .required_access_level = extract_required_access_level(request),
        .session_token = session_cookie.empty() ? std::nullopt
                                                : std::optional<std::string>(session_cookie),
    };
}

}  // namespace roche_limit::server::http
