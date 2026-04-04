#pragma once

#include "auth_core/login_repository.h"

#include <filesystem>
#include <vector>

namespace roche_limit::auth_store {

struct NewUserRecord {
    std::string username;
    std::optional<std::string> note;
};

struct UpdateUserRecord {
    bool note_is_set{false};
    std::optional<std::string> note;
    std::optional<bool> enabled;
};

struct NewUserServiceLevel {
    std::int64_t user_id;
    std::string service_name;
    int access_level;
    std::optional<std::string> note;
};

class UserRepository : public roche_limit::auth_core::LoginRepository {
public:
    explicit UserRepository(std::filesystem::path database_path);

    std::vector<roche_limit::auth_core::UserRecord> list_users() const;
    std::vector<roche_limit::auth_core::UserServiceLevelRecord> list_user_service_levels() const;

    std::optional<roche_limit::auth_core::UserRecord> find_enabled_user_by_username(
        std::string_view username) const override;
    std::optional<roche_limit::auth_core::UserRecord> find_enabled_user_by_id(
        std::int64_t user_id) const override;
    std::optional<roche_limit::auth_core::UserCredentialRecord> find_user_credential(
        std::int64_t user_id) const override;
    std::optional<roche_limit::auth_core::UserServiceLevelRecord> find_user_service_level(
        std::int64_t user_id,
        std::string_view service_name) const override;
    std::optional<roche_limit::auth_core::UserSessionRecord> find_active_user_session(
        std::string_view session_token_hash) const override;
    std::int64_t insert_user_session(std::int64_t user_id,
                                     std::string_view session_token_hash,
                                     std::string_view expires_at) const override;
    void update_user_session_last_seen(std::int64_t session_id) const override;
    void revoke_user_session(std::string_view session_token_hash) const override;

    std::int64_t insert_user(const NewUserRecord& new_user_record) const;
    void update_user(std::int64_t user_id, const UpdateUserRecord& update_user_record) const;
    void delete_user(std::int64_t user_id) const;
    void compact_user_ids() const;
    void upsert_user_credential(std::int64_t user_id, std::string_view password_hash) const;
    std::int64_t upsert_user_service_level(const NewUserServiceLevel& new_user_service_level) const;

private:
    std::filesystem::path database_path_;
};

}  // namespace roche_limit::auth_store
