#include "session_cookie_config.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {

using roche_limit::server::http::load_session_cookie_config;
using roche_limit::server::http::make_clear_session_cookie_header;
using roche_limit::server::http::make_session_cookie_header;

[[noreturn]] void fail(std::string_view message) {
    std::cerr << "test failure: " << message << std::endl;
    std::exit(1);
}

void expect(bool condition, std::string_view message) {
    if (!condition) {
        fail(message);
    }
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

void clear_cookie_env() {
    unsetenv("ROCHE_LIMIT_SESSION_COOKIE_NAME");
    unsetenv("ROCHE_LIMIT_SESSION_COOKIE_PATH");
    unsetenv("ROCHE_LIMIT_SESSION_COOKIE_DOMAIN");
    unsetenv("ROCHE_LIMIT_SESSION_COOKIE_SAMESITE");
    unsetenv("ROCHE_LIMIT_SESSION_COOKIE_SECURE");
    unsetenv("ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY");
    unsetenv("ROCHE_LIMIT_SESSION_COOKIE_MAX_AGE");
}

void test_default_cookie_attributes() {
    clear_cookie_env();
    const auto config = load_session_cookie_config();
    const auto cookie = make_session_cookie_header("token-value", config);

    expect(contains(cookie, "roche_limit_session=token-value"), "default cookie name should be used");
    expect(contains(cookie, "Path=/"), "default cookie path should be root");
    expect(contains(cookie, "HttpOnly"), "default cookie should be HttpOnly");
    expect(contains(cookie, "Secure"), "default cookie should be Secure");
    expect(contains(cookie, "SameSite=Lax"), "default SameSite should be Lax");
    expect(contains(cookie, "Max-Age=604800"), "default max age should be seven days");
}

void test_env_cookie_attributes() {
    clear_cookie_env();
    setenv("ROCHE_LIMIT_SESSION_COOKIE_NAME", "custom_session", 1);
    setenv("ROCHE_LIMIT_SESSION_COOKIE_PATH", "/web", 1);
    setenv("ROCHE_LIMIT_SESSION_COOKIE_DOMAIN", "example.com", 1);
    setenv("ROCHE_LIMIT_SESSION_COOKIE_SAMESITE", "None", 1);
    setenv("ROCHE_LIMIT_SESSION_COOKIE_SECURE", "0", 1);
    setenv("ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY", "0", 1);
    setenv("ROCHE_LIMIT_SESSION_COOKIE_MAX_AGE", "120", 1);

    const auto config = load_session_cookie_config();
    const auto cookie = make_session_cookie_header("token-value", config);
    const auto clear_cookie = make_clear_session_cookie_header(config);

    expect(contains(cookie, "custom_session=token-value"), "custom cookie name should be used");
    expect(contains(cookie, "Path=/web"), "custom cookie path should be used");
    expect(contains(cookie, "Domain=example.com"), "custom cookie domain should be used");
    expect(contains(cookie, "SameSite=None"), "custom SameSite should be used");
    expect(contains(cookie, "Max-Age=120"), "custom max age should be used");
    expect(!contains(cookie, "Secure"), "Secure should be configurable");
    expect(!contains(cookie, "HttpOnly"), "HttpOnly should be configurable");
    expect(contains(clear_cookie, "custom_session=deleted"), "clear cookie should use custom name");
    expect(contains(clear_cookie, "Max-Age=0"), "clear cookie should expire immediately");

    clear_cookie_env();
}

}  // namespace

int main() {
    test_default_cookie_attributes();
    test_env_cookie_attributes();

    std::cout << "roche_limit_session_cookie_config_tests: ok" << std::endl;
    return 0;
}
