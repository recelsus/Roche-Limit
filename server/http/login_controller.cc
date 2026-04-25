#include "login_controller.h"

#include "auth_core/auth_reason.h"
#include "auth_core/login_result.h"
#include "auth_core/login_service.h"
#include "auth_store/audit_repository.h"
#include "client_ip_resolver.h"
#include "common/debug_log.h"
#include "controller_support.h"
#include "login_page_renderer.h"
#include "request_extractor.h"
#include "request_observability.h"
#include "session_cookie_config.h"

#include <drogon/drogon.h>

#include <string>

namespace roche_limit::server::http {

namespace {

std::shared_ptr<const roche_limit::auth_core::LoginService> g_login_service;
std::shared_ptr<const roche_limit::auth_store::AuditRepository>
    g_login_audit_repository;

void add_session_cookie(const drogon::HttpResponsePtr &response,
                        std::string_view session_token) {
  const auto &config = session_cookie_config();
  response->addCookie(make_session_cookie(session_token, config));
}

void add_csrf_cookie(const drogon::HttpResponsePtr &response,
                     std::string_view csrf_token) {
  const auto &config = session_cookie_config();
  response->addCookie(make_csrf_cookie(csrf_token, config));
}

void clear_session_cookie(const drogon::HttpResponsePtr &response) {
  const auto &config = session_cookie_config();
  response->addCookie(make_clear_session_cookie(config));
}

void clear_csrf_cookie(const drogon::HttpResponsePtr &response) {
  const auto &config = session_cookie_config();
  response->addCookie(make_clear_csrf_cookie(config));
}

std::optional<std::string> extract_logout_csrf_token(
    const drogon::HttpRequestPtr &request) {
  const auto header_value = request->getHeader("X-CSRF-Token");
  if (!header_value.empty()) {
    return header_value;
  }
  const auto parameter_value = request->getParameter("csrf_token");
  if (!parameter_value.empty()) {
    return parameter_value;
  }
  return std::nullopt;
}

void handle_login_page(const drogon::HttpRequestPtr &request,
                       std::function<void(const drogon::HttpResponsePtr &)>
                           &&callback) {
  const auto request_id = next_request_id();
  const auto client_ip = resolve_request_client_ip(request);
  if (!g_login_service->can_access_login_page(client_ip)) {
    auto response = make_basic_response(drogon::k403Forbidden);
    add_request_id(response, request_id);
    record_auth_request("login_page", "deny",
                        roche_limit::auth_core::auth_reason::IpDeny);
    callback(response);
    return;
  }
  const auto csrf_token = g_login_service->issue_csrf_token("login", client_ip);
  auto response = make_login_page_response(csrf_token);
  add_request_id(response, request_id);
  add_csrf_cookie(response, csrf_token);
  record_auth_request("login_page", "allow", "page");
  callback(response);
}

void handle_login(
    const std::shared_ptr<const roche_limit::auth_core::LoginService>
        &login_service,
    const std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        &audit_repository,
    const drogon::HttpRequestPtr &request,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  const auto request_id = next_request_id();
  try {
    const auto login_request = build_login_request(request);
    const auto login_result = login_service->login(login_request);

    if (login_result.decision == roche_limit::auth_core::LoginDecision::Allow &&
        login_result.session_token.has_value()) {
      auto response = make_basic_response(drogon::k204NoContent);
      const auto logout_csrf_token =
          login_service->issue_csrf_token("logout", login_request.client_ip);
      add_request_id(response, request_id);
      add_session_cookie(response, *login_result.session_token);
      add_csrf_cookie(response, logout_csrf_token);
      record_auth_request("login", "allow", login_result.reason);
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = "login_success",
              .actor_type = "user",
              .actor_id = login_result.user_id.has_value()
                              ? std::optional<std::string>(
                                    std::to_string(*login_result.user_id))
                              : std::nullopt,
              .client_ip = login_request.client_ip,
              .request_id = request_id,
              .result = "success",
              .reason = login_result.reason,
          },
          "login_success");
      callback(response);
      return;
    }

    const bool invalid_csrf =
        login_result.reason == roche_limit::auth_core::auth_reason::InvalidCsrf;
    const bool rate_limited =
        login_result.reason == roche_limit::auth_core::auth_reason::RateLimited;
    const bool locked =
        login_result.reason == roche_limit::auth_core::auth_reason::Locked;
    auto response = make_basic_response(
        invalid_csrf ? drogon::k403Forbidden
                     : (rate_limited || locked ? drogon::k429TooManyRequests
                                               : drogon::k401Unauthorized));
    add_request_id(response, request_id);
    if (login_result.retry_after_seconds.has_value()) {
      response->addHeader("Retry-After",
                          std::to_string(*login_result.retry_after_seconds));
    }
    record_auth_request("login", "deny", login_result.reason);
    try_insert_audit_event(
        audit_repository,
        roche_limit::auth_store::NewAuditEvent{
            .event_type = invalid_csrf
                              ? "login_csrf_deny"
                              : (rate_limited ? "login_rate_limited"
                                              : (locked ? "login_locked"
                                                        : "login_failure")),
            .actor_type = "unknown",
            .client_ip = login_request.client_ip,
            .request_id = request_id,
            .result = "deny",
            .reason = login_result.reason,
        },
        "login_failure");
    callback(response);
  } catch (const std::exception &ex) {
    LOG_ERROR << "login handler failed request_id=" << request_id << ": "
              << ex.what();
    auto response = make_basic_response(drogon::k500InternalServerError);
    add_request_id(response, request_id);
    record_auth_request("login", "error",
                        roche_limit::auth_core::auth_reason::InternalError);
    callback(response);
  }
}

void deny_session_auth_request(
    std::string_view request_id,
    std::string_view service_name,
    std::string_view client_ip,
    std::string_view reason,
    const std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        &audit_repository,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback,
    std::string_view audit_context) {
  auto response = make_basic_response(drogon::k403Forbidden);
  add_request_id(response, request_id);
  response->addHeader("X-Auth-Level", "0");
  response->addHeader("X-Auth-Reason", std::string(reason));
  response->addHeader("X-Auth-Service",
                      service_name.empty() ? "*" : std::string(service_name));
  record_auth_request("session_auth", "deny", reason);
  try_insert_audit_event(
      audit_repository,
      roche_limit::auth_store::NewAuditEvent{
          .event_type = "session_auth_deny",
          .actor_type = "unknown",
          .service_name =
              service_name.empty() ? std::optional<std::string>("*")
                                   : std::optional<std::string>(
                                         std::string(service_name)),
          .client_ip = std::string(client_ip),
          .request_id = std::string(request_id),
          .result = "deny",
          .reason = std::string(reason),
      },
      audit_context);
  callback(response);
}

void handle_session_auth(
    const std::shared_ptr<const roche_limit::auth_core::LoginService>
        &login_service,
    const std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        &audit_repository,
    const drogon::HttpRequestPtr &request,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  const auto request_id = next_request_id();
  try {
    const auto peer_ip = request->peerAddr().toIp();
    if (!is_allowed_auth_peer(peer_ip)) {
      deny_session_auth_request(
          request_id, "*", peer_ip,
          roche_limit::auth_core::auth_reason::ForbiddenPeer, audit_repository,
          std::move(callback), "session_auth_forbidden_peer");
      return;
    }
    const auto auth_request = build_session_auth_request(request);
    if (auth_request.service_name.empty()) {
      deny_session_auth_request(
          request_id, "*", auth_request.client_ip,
          roche_limit::auth_core::auth_reason::MissingService, audit_repository,
          std::move(callback), "session_auth_missing_service");
      return;
    }
    if (!auth_request.required_access_level_present) {
      deny_session_auth_request(
          request_id, auth_request.service_name, auth_request.client_ip,
          roche_limit::auth_core::auth_reason::MissingRequiredLevel,
          audit_repository, std::move(callback),
          "session_auth_missing_required_level");
      return;
    }
    if (!auth_request.required_access_level_valid) {
      deny_session_auth_request(
          request_id, auth_request.service_name, auth_request.client_ip,
          roche_limit::auth_core::auth_reason::InvalidRequiredLevel,
          audit_repository, std::move(callback),
          "session_auth_invalid_required_level");
      return;
    }

    const auto auth_result = login_service->authorize_session(auth_request);
    auto response = make_basic_response(
        auth_result.decision == roche_limit::auth_core::LoginDecision::Allow
            ? drogon::k200OK
            : drogon::k403Forbidden);
    add_request_id(response, request_id);
    response->addHeader("X-Auth-Level",
                        std::to_string(auth_result.access_level));
    response->addHeader("X-Auth-Reason", auth_result.reason);
    response->addHeader("X-Auth-Service", auth_request.service_name);
    if (auth_result.user_id.has_value()) {
      response->addHeader("X-Auth-User-Id",
                          std::to_string(*auth_result.user_id));
    }
    if (auth_result.session_id.has_value()) {
      response->addHeader("X-Auth-Session-Id",
                          std::to_string(*auth_result.session_id));
    }
    record_auth_request("session_auth",
                        auth_result.decision ==
                                roche_limit::auth_core::LoginDecision::Allow
                            ? "allow"
                            : "deny",
                        auth_result.reason);
    if (auth_result.decision == roche_limit::auth_core::LoginDecision::Deny ||
        roche_limit::auth_store::audit_auth_allow_enabled()) {
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = auth_result.decision ==
                                    roche_limit::auth_core::LoginDecision::Allow
                                ? "session_auth_allow"
                                : "session_auth_deny",
              .actor_type = auth_result.user_id.has_value() ? "user" : "ip",
              .actor_id = auth_result.user_id.has_value()
                              ? std::optional<std::string>(
                                    std::to_string(*auth_result.user_id))
                              : std::nullopt,
              .target_type = "service",
              .target_id = auth_request.service_name,
              .service_name = auth_request.service_name,
              .access_level = auth_result.access_level,
              .client_ip = auth_request.client_ip,
              .request_id = request_id,
              .result = auth_result.decision ==
                                roche_limit::auth_core::LoginDecision::Allow
                            ? "allow"
                            : "deny",
              .reason = auth_result.reason,
          },
          "session_auth_result");
    }
    callback(response);
  } catch (const std::exception &ex) {
    LOG_ERROR << "session auth handler failed request_id=" << request_id << ": "
              << ex.what();
    auto response = make_basic_response(drogon::k500InternalServerError);
    add_request_id(response, request_id);
    record_auth_request("session_auth", "error",
                        roche_limit::auth_core::auth_reason::InternalError);
    callback(response);
  }
}

void handle_logout(
    const std::shared_ptr<const roche_limit::auth_core::LoginService>
        &login_service,
    const std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        &audit_repository,
    const drogon::HttpRequestPtr &request,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  const auto request_id = next_request_id();
  try {
    const auto peer_ip = request->peerAddr().toIp();
    if (!is_allowed_auth_peer(peer_ip)) {
      auto response = make_basic_response(drogon::k403Forbidden);
      add_request_id(response, request_id);
      clear_session_cookie(response);
      clear_csrf_cookie(response);
      record_auth_request("logout", "deny",
                          roche_limit::auth_core::auth_reason::ForbiddenPeer);
      callback(response);
      return;
    }
    const auto session_request = build_session_auth_request(request);
    const auto csrf_token = extract_logout_csrf_token(request);
    const auto csrf_cookie =
        request->getCookie(csrf_cookie_name(session_cookie_config()));
    if (!login_service->validate_csrf_token(
            "logout", session_request.client_ip, csrf_token,
            csrf_cookie.empty() ? std::nullopt
                                : std::optional<std::string_view>(csrf_cookie))) {
      auto response = make_basic_response(drogon::k403Forbidden);
      add_request_id(response, request_id);
      clear_session_cookie(response);
      clear_csrf_cookie(response);
      record_auth_request("logout", "deny",
                          roche_limit::auth_core::auth_reason::InvalidCsrf);
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = "logout_csrf_deny",
              .actor_type = "unknown",
              .client_ip = session_request.client_ip,
              .request_id = request_id,
              .result = "deny",
              .reason = roche_limit::auth_core::auth_reason::InvalidCsrf,
          },
          "logout_csrf_deny");
      callback(response);
      return;
    }
    if (session_request.session_token.has_value()) {
      login_service->logout(*session_request.session_token);
    }
    auto response = make_basic_response(drogon::k204NoContent);
    add_request_id(response, request_id);
    clear_session_cookie(response);
    clear_csrf_cookie(response);
    record_auth_request("logout", "allow",
                        roche_limit::auth_core::auth_reason::Logout);
    try_insert_audit_event(
        audit_repository,
        roche_limit::auth_store::NewAuditEvent{
            .event_type = "logout",
            .actor_type = "session",
            .request_id = request_id,
            .result = "success",
            .reason = roche_limit::auth_core::auth_reason::Logout,
        },
        "logout");
    callback(response);
  } catch (const std::exception &ex) {
    LOG_ERROR << "logout handler failed request_id=" << request_id << ": "
              << ex.what();
    auto response = make_basic_response(drogon::k500InternalServerError);
    add_request_id(response, request_id);
    record_auth_request("logout", "error",
                        roche_limit::auth_core::auth_reason::InternalError);
    callback(response);
  }
}

} // namespace

void register_login_routes(
    std::shared_ptr<const roche_limit::auth_core::LoginService> login_service,
    std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        audit_repository) {
  g_login_service = std::move(login_service);
  g_login_audit_repository = std::move(audit_repository);

  drogon::app().registerHandler(
      "/login",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_login_page(request, std::move(callback));
      },
      {drogon::Get});
  drogon::app().registerHandler(
      "/login/",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_login_page(request, std::move(callback));
      },
      {drogon::Get});

  drogon::app().registerHandler(
      "/login",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_login(g_login_service, g_login_audit_repository, request,
                     std::move(callback));
      },
      {drogon::Post});
  drogon::app().registerHandler(
      "/login/",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_login(g_login_service, g_login_audit_repository, request,
                     std::move(callback));
      },
      {drogon::Post});

  drogon::app().registerHandler(
      "/session/auth",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_session_auth(g_login_service, g_login_audit_repository, request,
                            std::move(callback));
      },
      {drogon::Get});
  drogon::app().registerHandler(
      "/session/auth/",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_session_auth(g_login_service, g_login_audit_repository, request,
                            std::move(callback));
      },
      {drogon::Get});

  drogon::app().registerHandler(
      "/logout",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_logout(g_login_service, g_login_audit_repository, request,
                      std::move(callback));
      },
      {drogon::Post});
  drogon::app().registerHandler(
      "/logout/",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        handle_logout(g_login_service, g_login_audit_repository, request,
                      std::move(callback));
      },
      {drogon::Post});
}

} // namespace roche_limit::server::http
