#include "auth_controller.h"

#include "auth_core/auth_reason.h"
#include "auth_core/auth_result.h"
#include "auth_core/auth_service.h"
#include "auth_store/audit_repository.h"
#include "common/debug_log.h"
#include "request_extractor.h"
#include "request_observability.h"

#include <drogon/drogon.h>

namespace roche_limit::server::http {

namespace {

drogon::HttpStatusCode
status_from_result(const roche_limit::auth_core::AuthResult &auth_result) {
  return auth_result.decision == roche_limit::auth_core::AuthDecision::Allow
             ? drogon::k200OK
             : drogon::k403Forbidden;
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

} // namespace

void register_auth_routes(
    std::shared_ptr<const roche_limit::auth_core::AuthService> auth_service,
    std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        audit_repository) {
  auto handler = [auth_service = std::move(auth_service),
                  audit_repository = std::move(audit_repository)](
                     const drogon::HttpRequestPtr &request,
                     std::function<void(const drogon::HttpResponsePtr &)>
                         &&callback) {
    const auto request_id = next_request_id();
    try {
      const auto request_context = build_request_context(request);
      if (roche_limit::common::verbose_logging_enabled()) {
        LOG_INFO << "auth request id=" << request_id
                 << " received service=" << request_context.service_name
                 << " client_ip=" << request_context.client_ip
                 << " api_key_present="
                 << (request_context.api_key.has_value() ? "yes" : "no");
      }
      if (request_context.service_name.empty()) {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k403Forbidden);
        response->addHeader("X-Request-Id", request_id);
        response->addHeader("X-Auth-Level", "0");
        response->addHeader(
            "X-Auth-Reason",
            roche_limit::auth_core::auth_reason::MissingService);
        response->addHeader("X-Auth-Service", "*");
        record_auth_request(
            "auth", "deny",
            roche_limit::auth_core::auth_reason::MissingService);
        try_insert_audit_event(
            audit_repository,
            roche_limit::auth_store::NewAuditEvent{
                .event_type = "auth_deny",
                .actor_type = "unknown",
                .service_name = std::string("*"),
                .client_ip = request_context.client_ip,
                .request_id = request_id,
                .result = "deny",
                .reason = roche_limit::auth_core::auth_reason::MissingService,
            },
            "auth_missing_service");
        callback(response);
        return;
      }

      if (roche_limit::common::verbose_logging_enabled()) {
        LOG_INFO << "auth request authorize begin";
      }
      const auto auth_result = auth_service->authorize(request_context);
      if (roche_limit::common::verbose_logging_enabled()) {
        LOG_INFO << "auth request id=" << request_id
                 << " authorize done decision="
                 << (auth_result.decision ==
                             roche_limit::auth_core::AuthDecision::Allow
                         ? "allow"
                         : "deny")
                 << " level=" << auth_result.access_level
                 << " reason=" << auth_result.reason;
      }

      auto response = drogon::HttpResponse::newHttpResponse();
      response->setStatusCode(status_from_result(auth_result));
      response->addHeader("X-Request-Id", request_id);
      response->addHeader("X-Auth-Level",
                          std::to_string(auth_result.access_level));
      response->addHeader("X-Auth-Reason", auth_result.reason);
      response->addHeader("X-Auth-Service", request_context.service_name.empty()
                                                ? "*"
                                                : request_context.service_name);

      if (auth_result.matched_ip_rule_id.has_value()) {
        response->addHeader("X-Auth-IP-Rule-Id",
                            std::to_string(*auth_result.matched_ip_rule_id));
      }
      if (auth_result.api_key_record_id.has_value()) {
        response->addHeader("X-Auth-Key-Id",
                            std::to_string(*auth_result.api_key_record_id));
      }

      record_auth_request("auth",
                          auth_result.decision ==
                                  roche_limit::auth_core::AuthDecision::Allow
                              ? "allow"
                              : "deny",
                          auth_result.reason);
      const bool audit_allow =
          roche_limit::auth_store::audit_auth_allow_enabled();
      if (auth_result.decision == roche_limit::auth_core::AuthDecision::Deny ||
          audit_allow) {
        try_insert_audit_event(
            audit_repository,
            roche_limit::auth_store::NewAuditEvent{
                .event_type =
                    auth_result.decision ==
                            roche_limit::auth_core::AuthDecision::Allow
                        ? "auth_allow"
                        : "auth_deny",
                .actor_type = auth_result.api_key_record_id.has_value()
                                  ? "api_key"
                                  : "ip",
                .actor_id = auth_result.api_key_record_id.has_value()
                                ? std::optional<std::string>(std::to_string(
                                      *auth_result.api_key_record_id))
                                : std::nullopt,
                .target_type = "service",
                .target_id = request_context.service_name,
                .service_name = request_context.service_name,
                .access_level = auth_result.access_level,
                .client_ip = request_context.client_ip,
                .request_id = request_id,
                .result = auth_result.decision ==
                                  roche_limit::auth_core::AuthDecision::Allow
                              ? "allow"
                              : "deny",
                .reason = auth_result.reason,
            },
            "auth_result");
      }
      callback(response);
    } catch (const std::exception &ex) {
      LOG_ERROR << "auth handler failed request_id=" << request_id << ": "
                << ex.what();
      auto response = drogon::HttpResponse::newHttpResponse();
      response->setStatusCode(drogon::k500InternalServerError);
      response->addHeader("X-Request-Id", request_id);
      response->addHeader("X-Auth-Level", "0");
      response->addHeader("X-Auth-Reason",
                          roche_limit::auth_core::auth_reason::InternalError);
      response->addHeader("X-Auth-Service", "*");
      record_auth_request("auth", "error",
                          roche_limit::auth_core::auth_reason::InternalError);
      try_insert_audit_event(
          audit_repository,
          roche_limit::auth_store::NewAuditEvent{
              .event_type = "auth_error",
              .actor_type = "unknown",
              .request_id = request_id,
              .result = "error",
              .reason = roche_limit::auth_core::auth_reason::InternalError,
              .metadata_json = std::string("{\"error\":\"handler_failed\"}"),
          },
          "auth_error");
      callback(response);
    }
  };

  drogon::app().registerHandler("/auth", handler, {drogon::Get});
  drogon::app().registerHandler("/auth/", handler, {drogon::Get});
}

} // namespace roche_limit::server::http
