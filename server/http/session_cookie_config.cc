#include "session_cookie_config.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <system_error>

namespace roche_limit::server::http {

namespace {

constexpr int kCsrfCookieMaxAgeSeconds = 600;
SessionCookieConfig g_session_cookie_config;

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

bool contains_control_character(std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::iscntrl(ch) != 0;
    });
}

void validate_cookie_component(std::string_view field_name, std::string_view value) {
    if (value.empty()) {
        throw std::runtime_error(std::string(field_name) + " must not be empty");
    }
    if (contains_control_character(value)) {
        throw std::runtime_error(std::string(field_name) + " contains control characters");
    }
}

SessionCookieConfig validate_session_cookie_config(SessionCookieConfig config) {
    validate_cookie_component("ROCHE_LIMIT_SESSION_COOKIE_NAME", config.name);
    validate_cookie_component("ROCHE_LIMIT_SESSION_COOKIE_PATH", config.path);
    if (!config.domain.empty()) {
        validate_cookie_component("ROCHE_LIMIT_SESSION_COOKIE_DOMAIN", config.domain);
    }

    config.same_site = normalize_same_site(config.same_site);
    if (config.same_site == "None") {
        config.secure = true;
    }
    if (config.name.rfind("__Host-", 0) == 0) {
        if (!config.secure) {
            throw std::runtime_error("__Host- cookie requires Secure");
        }
        if (!config.domain.empty()) {
            throw std::runtime_error("__Host- cookie must not set Domain");
        }
        if (config.path != "/") {
            throw std::runtime_error("__Host- cookie requires Path=/");
        }
    }
    if (config.name.rfind("__Secure-", 0) == 0 && !config.secure) {
        throw std::runtime_error("__Secure- cookie requires Secure");
    }

    return config;
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

SessionCookieConfig csrf_cookie_config_from(const SessionCookieConfig& config) {
    auto csrf_config = config;
    csrf_config.name = roche_limit::server::http::csrf_cookie_name(config);
    csrf_config.http_only = false;
    csrf_config.max_age_seconds = kCsrfCookieMaxAgeSeconds;
    return csrf_config;
}

drogon::Cookie make_cookie(std::string_view name,
                           std::string_view value,
                           const SessionCookieConfig& config,
                           int max_age_seconds) {
    drogon::Cookie cookie{std::string(name), std::string(value)};
    cookie.setPath(config.path);
    cookie.setHttpOnly(config.http_only);
    cookie.setSecure(config.secure);
    cookie.setMaxAge(max_age_seconds);
    if (!config.domain.empty()) {
        cookie.setDomain(config.domain);
    }
    if (config.same_site == "Strict") {
        cookie.setSameSite(drogon::Cookie::SameSite::kStrict);
    } else if (config.same_site == "None") {
        cookie.setSameSite(drogon::Cookie::SameSite::kNone);
    } else {
        cookie.setSameSite(drogon::Cookie::SameSite::kLax);
    }
    return cookie;
}

}  // namespace

SessionCookieConfig load_session_cookie_config() {
    return validate_session_cookie_config(SessionCookieConfig{
        .name = env_or_default("ROCHE_LIMIT_SESSION_COOKIE_NAME", "roche_limit_session"),
        .path = env_or_default("ROCHE_LIMIT_SESSION_COOKIE_PATH", "/"),
        .domain = env_or_default("ROCHE_LIMIT_SESSION_COOKIE_DOMAIN", ""),
        .same_site = normalize_same_site(env_or_default("ROCHE_LIMIT_SESSION_COOKIE_SAMESITE", "Lax")),
        .secure = env_bool_or_default("ROCHE_LIMIT_SESSION_COOKIE_SECURE", true),
        .http_only = env_bool_or_default("ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY", true),
        .max_age_seconds = env_int_or_default("ROCHE_LIMIT_SESSION_COOKIE_MAX_AGE", 604800),
    });
}

void initialize_session_cookie_config(SessionCookieConfig config) {
    g_session_cookie_config = validate_session_cookie_config(std::move(config));
}

void initialize_session_cookie_config_from_env() {
    initialize_session_cookie_config(load_session_cookie_config());
}

const SessionCookieConfig& session_cookie_config() {
    return g_session_cookie_config;
}

std::string csrf_cookie_name(const SessionCookieConfig& config) {
    return config.name + "_csrf";
}

drogon::Cookie make_session_cookie(std::string_view session_token,
                                   const SessionCookieConfig& config) {
    return make_cookie(config.name, session_token, config, config.max_age_seconds);
}

drogon::Cookie make_clear_session_cookie(const SessionCookieConfig& config) {
    return make_cookie(config.name, "deleted", config, 0);
}

drogon::Cookie make_csrf_cookie(std::string_view csrf_token,
                                const SessionCookieConfig& config) {
    const auto csrf_config = csrf_cookie_config_from(config);
    return make_cookie(csrf_config.name, csrf_token, csrf_config,
                       csrf_config.max_age_seconds);
}

drogon::Cookie make_clear_csrf_cookie(const SessionCookieConfig& config) {
    const auto csrf_config = csrf_cookie_config_from(config);
    return make_cookie(csrf_config.name, "deleted", csrf_config, 0);
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

std::string make_csrf_cookie_header(std::string_view csrf_token,
                                    const SessionCookieConfig& config) {
    return make_csrf_cookie(csrf_token, config).cookieString();
}

std::string make_clear_csrf_cookie_header(const SessionCookieConfig& config) {
    return make_clear_csrf_cookie(config).cookieString();
}

}  // namespace roche_limit::server::http
