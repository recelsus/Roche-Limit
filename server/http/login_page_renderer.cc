#include "login_page_renderer.h"

#include "login_asset_loader.h"

#include <drogon/HttpResponse.h>

#include <stdexcept>

namespace roche_limit::server::http {

namespace {

drogon::HttpResponsePtr make_asset_response(std::string_view asset_name,
                                            drogon::ContentType content_type) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k200OK);
    response->setContentTypeCode(content_type);
    response->setBody(load_login_asset(asset_name));
    return response;
}

}  // namespace

drogon::HttpResponsePtr make_login_page_response() {
    return make_asset_response("login.html", drogon::CT_TEXT_HTML);
}

drogon::HttpResponsePtr make_login_css_response() {
    return make_asset_response("login.css", drogon::CT_TEXT_CSS);
}

drogon::HttpResponsePtr make_login_js_response() {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k200OK);
    response->addHeader("Content-Type", "application/javascript; charset=utf-8");
    response->setBody(load_login_asset("login.js"));
    return response;
}

}  // namespace roche_limit::server::http
