#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace roche_limit::auth_core {

struct UserRecord {
    std::int64_t id;
    std::string username;
    bool enabled;
    std::optional<std::string> note;
    std::string created_at;
    std::string updated_at;
};

struct UserCredentialRecord {
    std::int64_t user_id;
    std::string password_hash;
    std::string password_updated_at;
    std::string created_at;
    std::string updated_at;
};

struct UserServiceLevelRecord {
    std::int64_t id;
    std::int64_t user_id;
    std::string service_name;
    int access_level;
    bool enabled;
    std::optional<std::string> note;
    std::string created_at;
    std::string updated_at;
};

struct UserSessionRecord {
    std::int64_t id;
    std::string session_token_hash;
    std::int64_t user_id;
    std::string absolute_expires_at;
    std::string idle_expires_at;
    std::string last_seen_at;
    std::string last_rotated_at;
    std::optional<std::string> revoked_at;
    std::string created_at;
    std::string updated_at;
};

struct LoginFailureRecord {
    std::int64_t id;
    std::string client_ip;
    std::string username;
    int failure_count;
    std::string last_failed_at;
    std::optional<std::string> locked_until;
    std::string created_at;
    std::string updated_at;
};

struct CsrfTokenRecord {
    std::int64_t id;
    std::string purpose;
    std::string token_hash;
    std::string client_ip;
    std::string expires_at;
    std::string created_at;
    std::string updated_at;
};

}  // namespace roche_limit::auth_core
