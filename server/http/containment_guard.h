#pragma once

#include <drogon/HttpTypes.h>

#include <optional>
#include <string>
#include <string_view>

namespace roche_limit::server::http {

struct ContainmentConfig {
  bool enabled{true};
  int deny_burst_window_seconds{60};
  int deny_burst_threshold{20};
  int quarantine_seconds{300};
  int lockdown_deny_burst_threshold{0};
  int lockdown_seconds{300};
};

struct ContainmentDecision {
  bool allowed{true};
  drogon::HttpStatusCode status_code{drogon::k200OK};
  std::string reason;
  std::optional<int> retry_after_seconds;
};

ContainmentConfig load_containment_config_from_env();
void initialize_containment_config(ContainmentConfig config);
void reset_containment_state_for_tests();

ContainmentDecision containment_decision(std::string_view client_ip);
void record_containment_signal(std::string_view endpoint,
                               std::string_view client_ip,
                               std::string_view result,
                               std::string_view reason);
std::string prometheus_containment_metrics_text();

} // namespace roche_limit::server::http
