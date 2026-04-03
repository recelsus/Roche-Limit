#pragma once

#include <drogon/HttpResponse.h>

namespace roche_limit::server::http {

drogon::HttpResponsePtr make_login_page_response();
drogon::HttpResponsePtr make_login_css_response();
drogon::HttpResponsePtr make_login_js_response();

}  // namespace roche_limit::server::http
