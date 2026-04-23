#include "session_cookie_config.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <string>
#include <system_error>

namespace roche_limit::server::http {

namespace {

std::string env_or_default(const char* name, std::string fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return value;
}

bool env_bool_or_default(const char* name, bool fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }

    std::string normalized(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

int env_int_or_default(const char* name, int fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }

    int parsed = fallback;
    const auto* begin = value;
    const auto* end = value + std::char_traits<char>::length(value);
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end || parsed < 0) {
        return fallback;
    }
    return parsed;
}

std::string normalize_same_site(std::string value) {
    if (value == "Strict" || value == "strict") {
        return "Strict";
    }
    if (value == "None" || value == "none") {
        return "None";
    }
    return "Lax";
}

std::string append_cookie_attributes(std::string cookie, const SessionCookieConfig& config, int max_age) {
    cookie += "; Path=" + config.path;
    if (!config.domain.empty()) {
        cookie += "; Domain=" + config.domain;
    }
    if (config.http_only) {
        cookie += "; HttpOnly";
    }
    if (config.secure) {
        cookie += "; Secure";
    }
    cookie += "; SameSite=" + config.same_site;
    cookie += "; Max-Age=" + std::to_string(max_age);
    return cookie;
}

}  // namespace

SessionCookieConfig load_session_cookie_config() {
    return SessionCookieConfig{
        .name = env_or_default("ROCHE_LIMIT_SESSION_COOKIE_NAME", "roche_limit_session"),
        .path = env_or_default("ROCHE_LIMIT_SESSION_COOKIE_PATH", "/"),
        .domain = env_or_default("ROCHE_LIMIT_SESSION_COOKIE_DOMAIN", ""),
        .same_site = normalize_same_site(env_or_default("ROCHE_LIMIT_SESSION_COOKIE_SAMESITE", "Lax")),
        .secure = env_bool_or_default("ROCHE_LIMIT_SESSION_COOKIE_SECURE", true),
        .http_only = env_bool_or_default("ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY", true),
        .max_age_seconds = env_int_or_default("ROCHE_LIMIT_SESSION_COOKIE_MAX_AGE", 604800),
    };
}

std::string make_session_cookie_header(std::string_view session_token,
                                       const SessionCookieConfig& config) {
    return append_cookie_attributes(config.name + "=" + std::string(session_token),
                                    config,
                                    config.max_age_seconds);
}

std::string make_clear_session_cookie_header(const SessionCookieConfig& config) {
    return append_cookie_attributes(config.name + "=deleted", config, 0);
}

}  // namespace roche_limit::server::http
