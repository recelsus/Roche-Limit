#include "request_extractor.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace roche_limit::server::http {

namespace {

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

std::optional<std::string> extract_api_key(const drogon::HttpRequestPtr& request) {
    const auto authorization = request->getHeader("Authorization");
    constexpr std::string_view kBearerPrefix = "Bearer ";
    if (authorization.starts_with(kBearerPrefix)) {
        return authorization.substr(kBearerPrefix.size());
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

roche_limit::auth_core::RequestContext build_request_context(
    const drogon::HttpRequestPtr& request) {
    auto client_ip = trim(request->getHeader("X-Real-IP"));
    if (client_ip.empty()) {
        client_ip = extract_forwarded_ip(request);
    }
    if (client_ip.empty()) {
        client_ip = request->peerAddr().toIp();
    }

    return roche_limit::auth_core::RequestContext{
        .client_ip = std::move(client_ip),
        .service_name = trim(request->getHeader("X-Target-Service")),
        .api_key = extract_api_key(request),
    };
}

}  // namespace roche_limit::server::http
