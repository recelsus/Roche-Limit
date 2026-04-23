#include "auth_store/user_repository.h"

#include "auth_store/sqlite_connection.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

namespace roche_limit::auth_store {

void UserRepository::compact_user_ids() const {
    static constexpr auto kSelectUserIdsSql = "SELECT id FROM users ORDER BY id ASC;";
    static constexpr auto kSelectUserServiceLevelIdsSql =
        "SELECT id FROM user_service_levels ORDER BY id ASC;";
    static constexpr auto kSelectUserSessionIdsSql =
        "SELECT id FROM user_sessions ORDER BY id ASC;";
    static constexpr auto kUpdateUserIdSql = "UPDATE users SET id = ?1 WHERE id = ?2;";
    static constexpr auto kUpdateCredentialUserIdSql =
        "UPDATE user_credentials SET user_id = ?1 WHERE user_id = ?2;";
    static constexpr auto kUpdateServiceLevelUserIdSql =
        "UPDATE user_service_levels SET user_id = ?1 WHERE user_id = ?2;";
    static constexpr auto kUpdateSessionUserIdSql =
        "UPDATE user_sessions SET user_id = ?1 WHERE user_id = ?2;";
    static constexpr auto kUpdateUserServiceLevelIdSql =
        "UPDATE user_service_levels SET id = ?1 WHERE id = ?2;";
    static constexpr auto kUpdateUserSessionIdSql =
        "UPDATE user_sessions SET id = ?1 WHERE id = ?2;";

    SqliteConnection connection(database_path_);
    auto* db = connection.handle();
    exec_sql(db, "PRAGMA foreign_keys = OFF;", "failed to disable foreign keys");
    exec_sql(db, "BEGIN IMMEDIATE;", "failed to begin transaction");
    try {
        const auto user_ids = select_ids(db, kSelectUserIdsSql, "failed to load user ids");
        for (std::size_t index = 0; index < user_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateCredentialUserIdSql,
                             user_ids[index],
                             temp_id,
                             "failed to move user credential references");
            update_single_id(db,
                             kUpdateServiceLevelUserIdSql,
                             user_ids[index],
                             temp_id,
                             "failed to move user service level references");
            update_single_id(db,
                             kUpdateSessionUserIdSql,
                             user_ids[index],
                             temp_id,
                             "failed to move user session references");
            update_single_id(db, kUpdateUserIdSql, user_ids[index], temp_id, "failed to move user id");
        }
        for (std::size_t index = 0; index < user_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            const auto new_id = static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateCredentialUserIdSql,
                             temp_id,
                             new_id,
                             "failed to restore user credential references");
            update_single_id(db,
                             kUpdateServiceLevelUserIdSql,
                             temp_id,
                             new_id,
                             "failed to restore user service level references");
            update_single_id(db,
                             kUpdateSessionUserIdSql,
                             temp_id,
                             new_id,
                             "failed to restore user session references");
            update_single_id(db, kUpdateUserIdSql, temp_id, new_id, "failed to restore user id");
        }

        const auto service_level_ids = select_ids(
            db, kSelectUserServiceLevelIdsSql, "failed to load user service level ids");
        for (std::size_t index = 0; index < service_level_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateUserServiceLevelIdSql,
                             service_level_ids[index],
                             temp_id,
                             "failed to move user service level id");
        }
        for (std::size_t index = 0; index < service_level_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            const auto new_id = static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateUserServiceLevelIdSql,
                             temp_id,
                             new_id,
                             "failed to restore user service level id");
        }

        const auto session_ids =
            select_ids(db, kSelectUserSessionIdsSql, "failed to load user session ids");
        for (std::size_t index = 0; index < session_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateUserSessionIdSql,
                             session_ids[index],
                             temp_id,
                             "failed to move user session id");
        }
        for (std::size_t index = 0; index < session_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            const auto new_id = static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateUserSessionIdSql,
                             temp_id,
                             new_id,
                             "failed to restore user session id");
        }

        exec_sql(db, "COMMIT;", "failed to commit transaction");
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
        throw;
    }
    exec_sql(db, "PRAGMA foreign_keys = ON;", "failed to re-enable foreign keys");
}

}  // namespace roche_limit::auth_store
