#include "login_controller.h"

#include "auth_core/auth_reason.h"
#include "auth_core/login_result.h"
#include "auth_core/login_service.h"
#include "common/debug_log.h"
#include "login_page_renderer.h"
#include "request_extractor.h"
#include "request_observability.h"
#include "session_cookie_config.h"

#include <drogon/drogon.h>

#include <string>

namespace roche_limit::server::http {

namespace {

drogon::HttpResponsePtr make_basic_response(drogon::HttpStatusCode status_code) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(status_code);
    return response;
}

void add_request_id(const drogon::HttpResponsePtr& response, std::string_view request_id) {
    response->addHeader("X-Request-Id", std::string(request_id));
}

void add_session_cookie(const drogon::HttpResponsePtr& response, std::string_view session_token) {
    response->addHeader("Set-Cookie",
                        make_session_cookie_header(session_token, load_session_cookie_config()));
}

void clear_session_cookie(const drogon::HttpResponsePtr& response) {
    response->addHeader("Set-Cookie",
                        make_clear_session_cookie_header(load_session_cookie_config()));
}

void handle_login(const std::shared_ptr<const roche_limit::auth_core::LoginService>& login_service,
                  const drogon::HttpRequestPtr& request,
                  std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
    const auto request_id = next_request_id();
    try {
        const auto login_request = build_login_request(request);
        const auto login_result = login_service->login(login_request);

        if (login_result.decision == roche_limit::auth_core::LoginDecision::Allow &&
            login_result.session_token.has_value()) {
            auto response = make_basic_response(drogon::k204NoContent);
            add_request_id(response, request_id);
            add_session_cookie(response, *login_result.session_token);
            record_auth_request("login", "allow", login_result.reason);
            callback(response);
            return;
        }

        auto response = make_basic_response(drogon::k401Unauthorized);
        add_request_id(response, request_id);
        record_auth_request("login", "deny", login_result.reason);
        callback(response);
    } catch (const std::exception& ex) {
        LOG_ERROR << "login handler failed request_id=" << request_id << ": " << ex.what();
        auto response = make_basic_response(drogon::k500InternalServerError);
        add_request_id(response, request_id);
        record_auth_request("login", "error", roche_limit::auth_core::auth_reason::InternalError);
        callback(response);
    }
}

void handle_session_auth(
    const std::shared_ptr<const roche_limit::auth_core::LoginService>& login_service,
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
    const auto request_id = next_request_id();
    try {
        const auto auth_request = build_session_auth_request(request);
        if (auth_request.service_name.empty()) {
            auto response = make_basic_response(drogon::k403Forbidden);
            add_request_id(response, request_id);
            response->addHeader("X-Auth-Level", "0");
            response->addHeader("X-Auth-Reason", roche_limit::auth_core::auth_reason::MissingService);
            response->addHeader("X-Auth-Service", "*");
            record_auth_request("session_auth", "deny", roche_limit::auth_core::auth_reason::MissingService);
            callback(response);
            return;
        }

        const auto auth_result = login_service->authorize_session(auth_request);
        auto response = make_basic_response(
            auth_result.decision == roche_limit::auth_core::LoginDecision::Allow
                ? drogon::k200OK
                : drogon::k403Forbidden);
        add_request_id(response, request_id);
        response->addHeader("X-Auth-Level", std::to_string(auth_result.access_level));
        response->addHeader("X-Auth-Reason", auth_result.reason);
        response->addHeader("X-Auth-Service", auth_request.service_name);
        if (auth_result.user_id.has_value()) {
            response->addHeader("X-Auth-User-Id", std::to_string(*auth_result.user_id));
        }
        if (auth_result.session_id.has_value()) {
            response->addHeader("X-Auth-Session-Id", std::to_string(*auth_result.session_id));
        }
        record_auth_request(
            "session_auth",
            auth_result.decision == roche_limit::auth_core::LoginDecision::Allow ? "allow" : "deny",
            auth_result.reason);
        callback(response);
    } catch (const std::exception& ex) {
        LOG_ERROR << "session auth handler failed request_id=" << request_id << ": " << ex.what();
        auto response = make_basic_response(drogon::k500InternalServerError);
        add_request_id(response, request_id);
        record_auth_request("session_auth", "error", roche_limit::auth_core::auth_reason::InternalError);
        callback(response);
    }
}

void handle_logout(const std::shared_ptr<const roche_limit::auth_core::LoginService>& login_service,
                   const drogon::HttpRequestPtr& request,
                   std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
    const auto request_id = next_request_id();
    try {
        const auto session_request = build_session_auth_request(request);
        if (session_request.session_token.has_value()) {
            login_service->logout(*session_request.session_token);
        }
        auto response = make_basic_response(drogon::k204NoContent);
        add_request_id(response, request_id);
        clear_session_cookie(response);
        record_auth_request("logout", "allow", roche_limit::auth_core::auth_reason::Logout);
        callback(response);
    } catch (const std::exception& ex) {
        LOG_ERROR << "logout handler failed request_id=" << request_id << ": " << ex.what();
        auto response = make_basic_response(drogon::k500InternalServerError);
        add_request_id(response, request_id);
        record_auth_request("logout", "error", roche_limit::auth_core::auth_reason::InternalError);
        callback(response);
    }
}

}  // namespace

void register_login_routes(std::shared_ptr<const roche_limit::auth_core::LoginService> login_service) {
    drogon::app().registerHandler(
        "/login",
        [](const drogon::HttpRequestPtr&,
           std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            const auto request_id = next_request_id();
            auto response = make_login_page_response();
            add_request_id(response, request_id);
            record_auth_request("login_page", "allow", "page");
            callback(response);
        },
        {drogon::Get});
    drogon::app().registerHandler(
        "/login/",
        [](const drogon::HttpRequestPtr&,
           std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            const auto request_id = next_request_id();
            auto response = make_login_page_response();
            add_request_id(response, request_id);
            record_auth_request("login_page", "allow", "page");
            callback(response);
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/login",
        [login_service](const drogon::HttpRequestPtr& request,
                        std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            handle_login(login_service, request, std::move(callback));
        },
        {drogon::Post});
    drogon::app().registerHandler(
        "/login/",
        [login_service](const drogon::HttpRequestPtr& request,
                        std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            handle_login(login_service, request, std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/session/auth",
        [login_service](const drogon::HttpRequestPtr& request,
                        std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            handle_session_auth(login_service, request, std::move(callback));
        },
        {drogon::Get});
    drogon::app().registerHandler(
        "/session/auth/",
        [login_service](const drogon::HttpRequestPtr& request,
                        std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            handle_session_auth(login_service, request, std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/logout",
        [login_service](const drogon::HttpRequestPtr& request,
                        std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            handle_logout(login_service, request, std::move(callback));
        },
        {drogon::Post});
    drogon::app().registerHandler(
        "/logout/",
        [login_service](const drogon::HttpRequestPtr& request,
                        std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            handle_logout(login_service, request, std::move(callback));
        },
        {drogon::Post});
}

}  // namespace roche_limit::server::http
