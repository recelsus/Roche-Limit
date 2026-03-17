#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace roche_limit::auth_core {

enum class AuthDecision {
    Allow,
    Deny,
};

struct AuthResult {
    AuthDecision decision;
    int access_level;
    std::string reason;
    std::optional<std::int64_t> matched_ip_rule_id;
    std::optional<std::int64_t> api_key_record_id;
};

}  // namespace roche_limit::auth_core
