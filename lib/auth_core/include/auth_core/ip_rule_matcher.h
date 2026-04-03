#pragma once

#include "ip_rule_record.h"

#include <optional>
#include <string_view>
#include <vector>

namespace roche_limit::auth_core {

bool is_valid_ip_address(std::string_view ip_text);

std::optional<IpRuleRecord> select_most_specific_ip_match(
    std::string_view client_ip,
    const std::vector<IpRuleRecord>& rules);

}  // namespace roche_limit::auth_core
