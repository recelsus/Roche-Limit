#include "auth_controller.h"

#include "auth_core/auth_result.h"
#include "auth_core/auth_service.h"
#include "request_extractor.h"

#include <drogon/drogon.h>

namespace roche_limit::server::http {

namespace {

drogon::HttpStatusCode status_from_result(const roche_limit::auth_core::AuthResult& auth_result) {
    return auth_result.decision == roche_limit::auth_core::AuthDecision::Allow
               ? drogon::k200OK
               : drogon::k403Forbidden;
}

}  // namespace

void register_auth_routes(std::shared_ptr<const roche_limit::auth_core::AuthService> auth_service) {
    auto handler =
        [auth_service = std::move(auth_service)](
            const drogon::HttpRequestPtr& request,
            std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            try {
                const auto request_context = build_request_context(request);
                LOG_INFO << "auth request received service=" << request_context.service_name
                         << " client_ip=" << request_context.client_ip
                         << " api_key_present=" << (request_context.api_key.has_value() ? "yes" : "no");
                if (request_context.service_name.empty()) {
                    auto response = drogon::HttpResponse::newHttpResponse();
                    response->setStatusCode(drogon::k403Forbidden);
                    response->addHeader("X-Auth-Level", "0");
                    response->addHeader("X-Auth-Reason", "missing_service");
                    response->addHeader("X-Auth-Service", "*");
                    callback(response);
                    return;
                }

                LOG_INFO << "auth request authorize begin";
                const auto auth_result = auth_service->authorize(request_context);
                LOG_INFO << "auth request authorize done decision="
                         << (auth_result.decision == roche_limit::auth_core::AuthDecision::Allow ? "allow"
                                                                                                 : "deny")
                         << " level=" << auth_result.access_level
                         << " reason=" << auth_result.reason;

                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(status_from_result(auth_result));
                response->addHeader("X-Auth-Level", std::to_string(auth_result.access_level));
                response->addHeader("X-Auth-Reason", auth_result.reason);
                response->addHeader("X-Auth-Service",
                                    request_context.service_name.empty() ? "*" : request_context.service_name);

                if (auth_result.matched_ip_rule_id.has_value()) {
                    response->addHeader("X-Auth-IP-Rule-Id",
                                        std::to_string(*auth_result.matched_ip_rule_id));
                }
                if (auth_result.api_key_record_id.has_value()) {
                    response->addHeader("X-Auth-Key-Id",
                                        std::to_string(*auth_result.api_key_record_id));
                }

                callback(response);
            } catch (const std::exception& ex) {
                LOG_ERROR << "auth handler failed: " << ex.what();
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k500InternalServerError);
                response->addHeader("X-Auth-Level", "0");
                response->addHeader("X-Auth-Reason", "internal_error");
                response->addHeader("X-Auth-Service", "*");
                callback(response);
            }
        };

    drogon::app().registerHandler(
        "/auth",
        handler,
        {drogon::Get, drogon::Post, drogon::Put, drogon::Delete, drogon::Patch, drogon::Options});
    drogon::app().registerHandler(
        "/auth/",
        handler,
        {drogon::Get, drogon::Post, drogon::Put, drogon::Delete, drogon::Patch, drogon::Options});
}

}  // namespace roche_limit::server::http
