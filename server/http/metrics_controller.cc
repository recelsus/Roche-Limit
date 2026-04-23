#include "metrics_controller.h"

#include "request_observability.h"

#include <drogon/drogon.h>

namespace roche_limit::server::http {

void register_metrics_routes() {
    drogon::app().registerHandler(
        "/metrics",
        [](const drogon::HttpRequestPtr&,
           std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setStatusCode(drogon::k200OK);
            response->setContentTypeCode(drogon::CT_TEXT_PLAIN);
            response->setBody(prometheus_metrics_text());
            callback(response);
        },
        {drogon::Get});
}

}  // namespace roche_limit::server::http
