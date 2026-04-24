#pragma once

#include "user_record.h"

#include <optional>
#include <string_view>

namespace roche_limit::auth_core {

class LoginRepository {
public:
    virtual ~LoginRepository() = default;

    virtual std::optional<UserRecord> find_enabled_user_by_username(
        std::string_view username) const = 0;
    virtual std::optional<UserRecord> find_enabled_user_by_id(std::int64_t user_id) const = 0;
    virtual std::optional<UserCredentialRecord> find_user_credential(std::int64_t user_id) const = 0;
    virtual std::optional<UserServiceLevelRecord> find_user_service_level(
        std::int64_t user_id,
        std::string_view service_name) const = 0;
    virtual std::optional<UserSessionRecord> find_active_user_session(
        std::string_view session_token_hash) const = 0;
    virtual std::int64_t insert_user_session(std::int64_t user_id,
                                             std::string_view session_token_hash,
                                             std::string_view expires_at) const = 0;
    virtual void update_user_session_last_seen(std::int64_t session_id) const = 0;
    virtual void revoke_user_session(std::string_view session_token_hash) const = 0;
    virtual std::optional<LoginFailureRecord> find_login_failure(
        std::string_view client_ip,
        std::string_view username) const = 0;
    virtual void upsert_login_failure(std::string_view client_ip,
                                      std::string_view username,
                                      int failure_count,
                                      std::optional<std::string_view> locked_until) const = 0;
    virtual void clear_login_failure(std::string_view client_ip,
                                     std::string_view username) const = 0;
    virtual void insert_csrf_token(std::string_view purpose,
                                   std::string_view token_hash,
                                   std::string_view client_ip,
                                   std::string_view expires_at) const = 0;
    virtual bool has_valid_csrf_token(std::string_view purpose,
                                      std::string_view token_hash,
                                      std::string_view client_ip) const = 0;
};

}  // namespace roche_limit::auth_core
