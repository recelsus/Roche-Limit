#pragma once

#include "auth_core/request_context.h"

#include <drogon/HttpRequest.h>

namespace roche_limit::server::http {

roche_limit::auth_core::RequestContext build_request_context(
    const drogon::HttpRequestPtr& request);

}  // namespace roche_limit::server::http
