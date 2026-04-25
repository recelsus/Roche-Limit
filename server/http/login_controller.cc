#include "login_controller.h"

#include "auth_core/auth_reason.h"
#include "auth_core/login_result.h"
#include "auth_core/login_service.h"
#include "auth_store/audit_repository.h"
#include "client_ip_resolver.h"
#include "common/debug_log.h"
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

drogon::HttpResponsePtr
make_basic_response(drogon::HttpStatusCode status_code) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(status_code);
  return response;
}

void add_cookie(const drogon::HttpResponsePtr &response,
                std::string_view name,
                std::string_view value,
                const roche_limit::server::http::SessionCookieConfig &config,
                bool http_only,
                int max_age_seconds) {
  drogon::Cookie cookie{std::string(name), std::string(value)};
  cookie.setPath(config.path);
  cookie.setHttpOnly(http_only);
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
  response->addCookie(std::move(cookie));
}

void add_request_id(const drogon::HttpResponsePtr &response,
                    std::string_view request_id) {
  response->addHeader("X-Request-Id", std::string(request_id));
}

void add_session_cookie(const drogon::HttpResponsePtr &response,
                        std::string_view session_token) {
  const auto &config = session_cookie_config();
  add_cookie(response, config.name, session_token, config, config.http_only,
             config.max_age_seconds);
}

void add_csrf_cookie(const drogon::HttpResponsePtr &response,
                     std::string_view csrf_token) {
  const auto &config = session_cookie_config();
  add_cookie(response, csrf_cookie_name(config), csrf_token, config, false, 600);
}

void clear_session_cookie(const drogon::HttpResponsePtr &response) {
  const auto &config = session_cookie_config();
  add_cookie(response, config.name, "deleted", config, config.http_only, 0);
}

void clear_csrf_cookie(const drogon::HttpResponsePtr &response) {
  const auto &config = session_cookie_config();
  add_cookie(response, csrf_cookie_name(config), "deleted", config, false, 0);
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

void try_insert_audit_event(
    const std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        &audit_repository,
    const roche_limit::auth_store::NewAuditEvent &event,
    std::string_view context) {
  try {
    audit_repository->insert_event(event);
  } catch (const std::exception &ex) {
    LOG_ERROR << "audit insert failed context=" << context << ": " << ex.what();
  } catch (...) {
    LOG_ERROR << "audit insert failed context=" << context << ": unknown error";
  }
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
      auto response = make_basic_response(drogon::k403Forbidden);
      add_request_id(response, request_id);
      response->addHeader("X-Auth-Level", "0");
      response->addHeader("X-Auth-Reason",
                          roche_limit::auth_core::auth_reason::ForbiddenPeer);
      response->addHeader("X-Auth-Service", "*");
      record_auth_request("session_auth", "deny",
                          roche_limit::auth_core::auth_reason::ForbiddenPeer);
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = "session_auth_deny",
              .actor_type = "unknown",
              .service_name = std::string("*"),
              .client_ip = peer_ip,
              .request_id = request_id,
              .result = "deny",
              .reason = roche_limit::auth_core::auth_reason::ForbiddenPeer,
          },
          "session_auth_forbidden_peer");
      callback(response);
      return;
    }
    const auto auth_request = build_session_auth_request(request);
    if (auth_request.service_name.empty()) {
      auto response = make_basic_response(drogon::k403Forbidden);
      add_request_id(response, request_id);
      response->addHeader("X-Auth-Level", "0");
      response->addHeader("X-Auth-Reason",
                          roche_limit::auth_core::auth_reason::MissingService);
      response->addHeader("X-Auth-Service", "*");
      record_auth_request("session_auth", "deny",
                          roche_limit::auth_core::auth_reason::MissingService);
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = "session_auth_deny",
              .actor_type = "unknown",
              .service_name = std::string("*"),
              .client_ip = auth_request.client_ip,
              .request_id = request_id,
              .result = "deny",
              .reason = roche_limit::auth_core::auth_reason::MissingService,
          },
          "session_auth_missing_service");
      callback(response);
      return;
    }
    if (!auth_request.required_access_level_present) {
      auto response = make_basic_response(drogon::k403Forbidden);
      add_request_id(response, request_id);
      response->addHeader("X-Auth-Level", "0");
      response->addHeader(
          "X-Auth-Reason",
          roche_limit::auth_core::auth_reason::MissingRequiredLevel);
      response->addHeader("X-Auth-Service", auth_request.service_name);
      record_auth_request(
          "session_auth", "deny",
          roche_limit::auth_core::auth_reason::MissingRequiredLevel);
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = "session_auth_deny",
              .actor_type = "unknown",
              .service_name = auth_request.service_name,
              .client_ip = auth_request.client_ip,
              .request_id = request_id,
              .result = "deny",
              .reason =
                  roche_limit::auth_core::auth_reason::MissingRequiredLevel,
          },
          "session_auth_missing_required_level");
      callback(response);
      return;
    }
    if (!auth_request.required_access_level_valid) {
      auto response = make_basic_response(drogon::k403Forbidden);
      add_request_id(response, request_id);
      response->addHeader("X-Auth-Level", "0");
      response->addHeader(
          "X-Auth-Reason",
          roche_limit::auth_core::auth_reason::InvalidRequiredLevel);
      response->addHeader("X-Auth-Service", auth_request.service_name);
      record_auth_request(
          "session_auth", "deny",
          roche_limit::auth_core::auth_reason::InvalidRequiredLevel);
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = "session_auth_deny",
              .actor_type = "unknown",
              .service_name = auth_request.service_name,
              .client_ip = auth_request.client_ip,
              .request_id = request_id,
              .result = "deny",
              .reason =
                  roche_limit::auth_core::auth_reason::InvalidRequiredLevel,
          },
          "session_auth_invalid_required_level");
      callback(response);
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
        const auto csrf_token =
            g_login_service->issue_csrf_token("login", client_ip);
        auto response = make_login_page_response(csrf_token);
        add_request_id(response, request_id);
        add_csrf_cookie(response, csrf_token);
        record_auth_request("login_page", "allow", "page");
        callback(response);
      },
      {drogon::Get});
  drogon::app().registerHandler(
      "/login/",
      [](const drogon::HttpRequestPtr &request,
         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
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
        const auto csrf_token =
            g_login_service->issue_csrf_token("login", client_ip);
        auto response = make_login_page_response(csrf_token);
        add_request_id(response, request_id);
        add_csrf_cookie(response, csrf_token);
        record_auth_request("login_page", "allow", "page");
        callback(response);
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
