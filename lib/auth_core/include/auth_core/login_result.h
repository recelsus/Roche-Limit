#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace roche_limit::auth_core {

enum class LoginDecision {
    Allow,
    Deny,
};

struct LoginResult {
    LoginDecision decision;
    std::string reason;
    std::optional<std::int64_t> user_id;
    std::optional<std::string> session_token;
    std::optional<std::string> expires_at;
};

struct SessionAuthResult {
    LoginDecision decision;
    int access_level;
    std::string reason;
    std::optional<std::int64_t> user_id;
    std::optional<std::int64_t> session_id;
};

}  // namespace roche_limit::auth_core
