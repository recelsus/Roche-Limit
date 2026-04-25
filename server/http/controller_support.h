#pragma once

#include "auth_store/audit_repository.h"

#include <drogon/HttpResponse.h>
#include <trantor/utils/Logger.h>

#include <memory>
#include <string_view>

namespace roche_limit::server::http {

inline drogon::HttpResponsePtr
make_basic_response(drogon::HttpStatusCode status_code) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(status_code);
  return response;
}

inline void add_request_id(const drogon::HttpResponsePtr &response,
                           std::string_view request_id) {
  response->addHeader("X-Request-Id", std::string(request_id));
}

inline void try_insert_audit_event(
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

} // namespace roche_limit::server::http
