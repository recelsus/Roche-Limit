#include "auth_controller.h"

#include "auth_core/auth_reason.h"
#include "auth_core/auth_result.h"
#include "auth_core/auth_service.h"
#include "auth_store/audit_repository.h"
#include "auth_endpoint_guard.h"
#include "client_ip_resolver.h"
#include "common/debug_log.h"
#include "containment_guard.h"
#include "controller_support.h"
#include "request_extractor.h"
#include "request_observability.h"

#include <drogon/drogon.h>

#include <cstdlib>
#include <optional>
#include <string_view>
#include <vector>

namespace roche_limit::server::http {

namespace {

std::shared_ptr<const roche_limit::auth_core::AuthService> g_auth_service;
std::shared_ptr<const roche_limit::auth_store::AuditRepository>
    g_auth_audit_repository;

drogon::HttpStatusCode
status_from_result(const roche_limit::auth_core::AuthResult &auth_result) {
  return auth_result.decision == roche_limit::auth_core::AuthDecision::Allow
             ? drogon::k200OK
             : drogon::k403Forbidden;
}

void deny_request(std::string_view request_id,
                  std::string_view service_name,
                  std::string_view client_ip,
                  std::string_view reason,
                  const std::function<void(const drogon::HttpResponsePtr &)>& callback,
                  std::string_view audit_context,
                  drogon::HttpStatusCode status_code = drogon::k403Forbidden,
                  std::optional<int> retry_after_seconds = std::nullopt) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(status_code);
  response->addHeader("X-Request-Id", std::string(request_id));
  response->addHeader("X-Auth-Level", "0");
  response->addHeader("X-Auth-Reason", std::string(reason));
  response->addHeader("X-Auth-Service",
                      service_name.empty() ? "*" : std::string(service_name));
  if (retry_after_seconds.has_value()) {
    response->addHeader("Retry-After", std::to_string(*retry_after_seconds));
  }
  record_auth_request("auth", "deny", reason);
  record_containment_signal("auth", client_ip, "deny", reason);
  try_insert_audit_event(
      g_auth_audit_repository,
      roche_limit::auth_store::NewAuditEvent{
          .event_type = "auth_deny",
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

bool has_invalid_single_value_auth_header(
    const drogon::HttpRequestPtr &request) {
  return has_multiple_single_value_header_values(
             request->getHeader("X-Target-Service")) ||
         has_multiple_single_value_header_values(
             request->getHeader("X-Required-Level")) ||
         has_multiple_single_value_header_values(
             request->getHeader("Authorization")) ||
         has_multiple_single_value_header_values(request->getHeader("X-API-Key")) ||
         has_multiple_single_value_header_values(request->getHeader("X-Real-IP"));
}

std::string_view deployment_mode_env() {
  const char *value = std::getenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  return value == nullptr ? std::string_view{} : std::string_view(value);
}

bool public_like_deployment_mode() {
  const auto mode = deployment_mode_env();
  return mode == "public" || mode == "hardened";
}

bool hardened_deployment_mode() {
  return deployment_mode_env() == "hardened";
}

bool has_multiple_auth_credentials(const drogon::HttpRequestPtr &request) {
  return !request->getHeader("Authorization").empty() &&
         !request->getHeader("X-API-Key").empty();
}

} // namespace

void register_auth_routes(
    std::shared_ptr<const roche_limit::auth_core::AuthService> auth_service,
    std::shared_ptr<const roche_limit::auth_store::AuditRepository>
        audit_repository) {
  g_auth_service = std::move(auth_service);
  g_auth_audit_repository = std::move(audit_repository);

  auto handler = [](const drogon::HttpRequestPtr &request,
                    std::function<void(const drogon::HttpResponsePtr &)>
                        &&callback) {
    const auto request_id = next_request_id();
    try {
      const auto peer_ip = request->peerAddr().toIp();
      if (const auto containment = containment_decision(peer_ip);
          !containment.allowed) {
        deny_request(request_id, "*", peer_ip, containment.reason, callback,
                     "auth_containment", containment.status_code,
                     containment.retry_after_seconds);
        return;
      }
      const auto guard_result =
          guard_auth_endpoint_request(request, "auth", peer_ip);
      if (!guard_result.allowed) {
        deny_request(request_id, "*", peer_ip, guard_result.reason, callback,
                     "auth_guard", guard_result.status_code,
                     guard_result.retry_after_seconds);
        return;
      }
      if (!is_allowed_auth_peer(peer_ip)) {
        deny_request(request_id, "*", peer_ip,
                     roche_limit::auth_core::auth_reason::ForbiddenPeer,
                     callback, "auth_forbidden_peer");
        return;
      }
      if (has_invalid_single_value_auth_header(request)) {
        deny_request(request_id, "*", peer_ip,
                     roche_limit::auth_core::auth_reason::InvalidHeader,
                     callback, "auth_invalid_header");
        return;
      }
      if (hardened_deployment_mode() && has_multiple_auth_credentials(request)) {
        deny_request(request_id, "*", peer_ip,
                     roche_limit::auth_core::auth_reason::InvalidHeader,
                     callback, "auth_multiple_credentials");
        return;
      }
      if (forwarded_client_ip_headers_conflict(
              request->getHeader("X-Real-IP"),
              request->getHeader("X-Forwarded-For"))) {
        deny_request(
            request_id, "*", peer_ip,
            roche_limit::auth_core::auth_reason::ConflictingForwardedHeaders,
            callback, "auth_conflicting_forwarded_headers");
        return;
      }
      if (public_like_deployment_mode() &&
          !request->getHeader("X-Forwarded-For").empty() &&
          !forwarded_for_chain_is_valid(request->getHeader("X-Forwarded-For"))) {
        deny_request(request_id, "*", peer_ip,
                     roche_limit::auth_core::auth_reason::InvalidHeader,
                     callback, "auth_invalid_forwarded_for");
        return;
      }
      if (roche_limit::common::verbose_logging_enabled()) {
        LOG_INFO << "auth handler auth_service="
                 << static_cast<const void *>(g_auth_service.get())
                 << " repository="
                 << static_cast<const void *>(
                        g_auth_service->repository_address());
      }
      const auto request_context = build_request_context(request);
      if (const auto containment =
              containment_decision(request_context.client_ip);
          !containment.allowed) {
        deny_request(request_id, "*", request_context.client_ip,
                     containment.reason, callback, "auth_containment_client",
                     containment.status_code, containment.retry_after_seconds);
        return;
      }
      if (request_context.service_name.empty()) {
        deny_request(request_id, "*", request_context.client_ip,
                     roche_limit::auth_core::auth_reason::MissingService,
                     callback, "auth_missing_service");
        return;
      }
      if (!request_context.service_name_valid) {
        deny_request(request_id, "*", request_context.client_ip,
                     roche_limit::auth_core::auth_reason::InvalidService,
                     callback, "auth_invalid_service");
        return;
      }
      if (!request_context.required_access_level_present) {
        deny_request(
            request_id, request_context.service_name, request_context.client_ip,
            roche_limit::auth_core::auth_reason::MissingRequiredLevel,
            callback, "auth_missing_required_level");
        return;
      }
      if (!request_context.required_access_level_valid) {
        deny_request(
            request_id, request_context.service_name, request_context.client_ip,
            roche_limit::auth_core::auth_reason::InvalidRequiredLevel,
            callback, "auth_invalid_required_level");
        return;
      }

      if (roche_limit::common::verbose_logging_enabled()) {
        LOG_INFO << "auth request id=" << request_id
                 << " received service=" << request_context.service_name
                 << " client_ip=" << request_context.client_ip
                 << " api_key_present="
                 << (request_context.api_key.has_value() ? "yes" : "no");
        LOG_INFO << "auth request authorize begin";
      }
      const auto auth_result = g_auth_service->authorize(request_context);
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
      if (auth_result.api_key_record_id.has_value()) {
        const auto subject = ContainmentSubject{
            .type = "api_key",
            .id = std::to_string(*auth_result.api_key_record_id),
        };
        if (const auto containment = containment_decision_for_subject(subject);
            !containment.allowed) {
          deny_request(request_id, request_context.service_name,
                       request_context.client_ip, containment.reason, callback,
                       "auth_api_key_containment", containment.status_code,
                       containment.retry_after_seconds);
          return;
        }
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
      record_containment_signal(
          "auth", request_context.client_ip,
          auth_result.decision ==
                  roche_limit::auth_core::AuthDecision::Allow
              ? "allow"
              : "deny",
          auth_result.reason);
      if (auth_result.api_key_record_id.has_value()) {
        record_containment_signal_for_subject(
            ContainmentSubject{
                .type = "api_key",
                .id = std::to_string(*auth_result.api_key_record_id),
            },
            "auth",
            auth_result.decision ==
                    roche_limit::auth_core::AuthDecision::Allow
                ? "allow"
                : "deny",
            auth_result.reason);
      }
      const bool audit_allow =
          roche_limit::auth_store::audit_auth_allow_enabled();
      if (auth_result.decision == roche_limit::auth_core::AuthDecision::Deny ||
          audit_allow) {
        try_insert_audit_event(
            g_auth_audit_repository,
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
          g_auth_audit_repository,
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

  const std::vector<drogon::internal::HttpConstraint> auth_methods{
      drogon::Get, drogon::Post, drogon::Put, drogon::Delete, drogon::Options,
      drogon::Patch};
  drogon::app().registerHandler("/auth", handler, auth_methods);
  drogon::app().registerHandler("/auth/", handler, auth_methods);
}

} // namespace roche_limit::server::http
