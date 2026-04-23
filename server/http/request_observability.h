#pragma once

#include <string>
#include <string_view>

namespace roche_limit::server::http {

std::string next_request_id();

void record_auth_request(std::string_view endpoint,
                         std::string_view result,
                         std::string_view reason);

std::string prometheus_metrics_text();

}  // namespace roche_limit::server::http
