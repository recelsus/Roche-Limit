#include "metrics_controller.h"

#include "client_ip_resolver.h"
#include "request_observability.h"

#include <drogon/drogon.h>

#include <cstdlib>
#include <string_view>
#include <vector>

namespace roche_limit::server::http {

namespace {

std::string_view metrics_mode() {
    const char* value = std::getenv("ROCHE_LIMIT_METRICS_MODE");
    if (value == nullptr || *value == '\0') {
        return "enabled";
    }
    const std::string_view mode(value);
    if (mode == "disabled" || mode == "internal" || mode == "enabled") {
        return mode;
    }
    return "enabled";
}

}  // namespace

void register_metrics_routes() {
    const std::vector<drogon::internal::HttpConstraint> methods{
        drogon::Get, drogon::Post, drogon::Put, drogon::Delete, drogon::Options,
        drogon::Patch};
    drogon::app().registerHandler(
        "/metrics",
        [](const drogon::HttpRequestPtr& request,
           std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            auto response = drogon::HttpResponse::newHttpResponse();
            if (request->method() != drogon::Get || request->isHead()) {
                response->setStatusCode(drogon::k405MethodNotAllowed);
                callback(response);
                return;
            }
            const auto mode = metrics_mode();
            if (mode == "disabled") {
                response->setStatusCode(drogon::k404NotFound);
                callback(response);
                return;
            }
            if (mode == "internal" &&
                !is_allowed_auth_peer(request->peerAddr().toIp())) {
                response->setStatusCode(drogon::k403Forbidden);
                callback(response);
                return;
            }
            response->setStatusCode(drogon::k200OK);
            response->setContentTypeCode(drogon::CT_TEXT_PLAIN);
            response->setBody(prometheus_metrics_text());
            callback(response);
        },
        methods);
}

}  // namespace roche_limit::server::http
