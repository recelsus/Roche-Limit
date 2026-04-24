#pragma once

#include <drogon/HttpResponse.h>
#include <string_view>

namespace roche_limit::server::http {

drogon::HttpResponsePtr make_login_page_response(std::string_view csrf_token);

}  // namespace roche_limit::server::http
