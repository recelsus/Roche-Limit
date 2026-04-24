#include "login_page_renderer.h"

#include "login_asset_loader.h"

#include <drogon/HttpResponse.h>

#include <stdexcept>

namespace roche_limit::server::http {

namespace {

constexpr std::string_view kInlineCssPlaceholder = "__INLINE_LOGIN_CSS__";
constexpr std::string_view kInlineJsPlaceholder = "__INLINE_LOGIN_JS__";
constexpr std::string_view kCsrfTokenPlaceholder = "__LOGIN_CSRF_TOKEN__";

std::string render_login_page(std::string_view csrf_token) {
    auto html = load_login_asset("login.html");
    const auto css = load_login_asset("login.css");
    const auto js = load_login_asset("login.js");

    if (const auto css_position = html.find(kInlineCssPlaceholder);
        css_position != std::string::npos) {
        html.replace(css_position, kInlineCssPlaceholder.size(), css);
    }
    if (const auto js_position = html.find(kInlineJsPlaceholder);
        js_position != std::string::npos) {
        html.replace(js_position, kInlineJsPlaceholder.size(), js);
    }
    std::size_t token_position = html.find(kCsrfTokenPlaceholder);
    while (token_position != std::string::npos) {
        html.replace(token_position, kCsrfTokenPlaceholder.size(), csrf_token);
        token_position = html.find(kCsrfTokenPlaceholder,
                                   token_position + csrf_token.size());
    }

    return html;
}

drogon::HttpResponsePtr make_html_response(std::string body) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k200OK);
    response->setContentTypeCode(drogon::CT_TEXT_HTML);
    response->setBody(std::move(body));
    return response;
}

}  // namespace

drogon::HttpResponsePtr make_login_page_response(std::string_view csrf_token) {
    return make_html_response(render_login_page(csrf_token));
}

}  // namespace roche_limit::server::http
