#include "root_controller.h"

#include <drogon/drogon.h>

namespace roche_limit::server::http {

void register_root_routes() {
    drogon::app().registerHandler("/", [](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        Json::Value payload;
        payload["status"] = "ok";
        payload["service"] = "roche-limit";
        callback(drogon::HttpResponse::newHttpJsonResponse(payload));
    });
}

}  // namespace roche_limit::server::http
