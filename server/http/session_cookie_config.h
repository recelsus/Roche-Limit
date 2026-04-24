#pragma once

#include <string>
#include <string_view>

namespace roche_limit::server::http {

struct SessionCookieConfig {
    std::string name;
    std::string path;
    std::string domain;
    std::string same_site;
    bool secure;
    bool http_only;
    int max_age_seconds;
};

SessionCookieConfig load_session_cookie_config();
void initialize_session_cookie_config(SessionCookieConfig config);
void initialize_session_cookie_config_from_env();
const SessionCookieConfig& session_cookie_config();
std::string csrf_cookie_name(const SessionCookieConfig& config);

std::string make_session_cookie_header(std::string_view session_token,
                                       const SessionCookieConfig& config);
std::string make_clear_session_cookie_header(const SessionCookieConfig& config);
std::string make_csrf_cookie_header(std::string_view csrf_token,
                                    const SessionCookieConfig& config);
std::string make_clear_csrf_cookie_header(const SessionCookieConfig& config);

}  // namespace roche_limit::server::http
