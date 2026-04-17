#pragma once

#include "auth_core/ip_rule_record.h"

#include <string>
#include <string_view>
#include <vector>

namespace roche_limit::server::http {

std::vector<roche_limit::auth_core::IpRuleRecord> parse_trusted_proxy_rules(
    std::string_view trusted_proxies_text);

std::vector<roche_limit::auth_core::IpRuleRecord> load_trusted_proxy_rules_from_env();

std::string resolve_client_ip(std::string_view peer_ip,
                              std::string_view real_ip_header,
                              std::string_view forwarded_for_header,
                              const std::vector<roche_limit::auth_core::IpRuleRecord>& trusted_proxy_rules);

}  // namespace roche_limit::server::http
