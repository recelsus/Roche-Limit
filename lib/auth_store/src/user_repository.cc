#include "auth_store/user_repository.h"

#include "auth_store/sqlite_connection.h"

#include <sqlite3.h>

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace roche_limit::auth_store {

namespace {

using roche_limit::auth_core::UserCredentialRecord;
using roche_limit::auth_core::UserRecord;
using roche_limit::auth_core::UserServiceLevelRecord;
using roche_limit::auth_core::UserSessionRecord;
using roche_limit::auth_store::NewUserRecord;
using roche_limit::auth_store::NewUserServiceLevel;
using roche_limit::auth_store::UpdateUserRecord;

class Statement final {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db_, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("failed to prepare sqlite statement: ") +
                                     sqlite3_errmsg(db_));
        }
    }

    ~Statement() {
        if (statement_ != nullptr) {
            sqlite3_finalize(statement_);
        }
    }

    sqlite3_stmt* get() const noexcept {
        return statement_;
    }

private:
    sqlite3* db_{nullptr};
    sqlite3_stmt* statement_{nullptr};
};

void bind_text(sqlite3_stmt* statement, int index, std::string_view value) {
    if (sqlite3_bind_text(statement,
                          index,
                          value.data(),
                          static_cast<int>(value.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite text parameter");
    }
}

void bind_int64(sqlite3_stmt* statement, int index, std::int64_t value) {
    if (sqlite3_bind_int64(statement, index, value) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
}

std::optional<std::string> nullable_text(sqlite3_stmt* statement, int column) {
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        return std::nullopt;
    }
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    return text != nullptr ? std::optional<std::string>(text) : std::nullopt;
}

void exec_sql(sqlite3* db, const char* sql, const char* message) {
    char* error_message = nullptr;
    const auto result = sqlite3_exec(db, sql, nullptr, nullptr, &error_message);
    if (result != SQLITE_OK) {
        std::string full_message = message;
        if (error_message != nullptr) {
            full_message += ": ";
            full_message += error_message;
            sqlite3_free(error_message);
        }
        throw std::runtime_error(full_message);
    }
}

std::vector<std::int64_t> select_ids(sqlite3* db, const char* sql, const char* message) {
    Statement statement(db, sql);
    std::vector<std::int64_t> ids;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error(message);
        }
        ids.push_back(sqlite3_column_int64(statement.get(), 0));
    }
    return ids;
}

void update_single_id(sqlite3* db,
                      const char* sql,
                      std::int64_t old_id,
                      std::int64_t new_id,
                      const char* message) {
    Statement statement(db, sql);
    bind_int64(statement.get(), 1, new_id);
    bind_int64(statement.get(), 2, old_id);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error(message);
    }
}

UserRecord read_user(sqlite3_stmt* statement) {
    const auto* username = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 4));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 5));
    return UserRecord{
        .id = sqlite3_column_int64(statement, 0),
        .username = username != nullptr ? username : "",
        .enabled = sqlite3_column_int(statement, 2) != 0,
        .note = nullable_text(statement, 3),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

UserCredentialRecord read_user_credential(sqlite3_stmt* statement) {
    const auto* password_hash = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
    const auto* password_updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 2));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 3));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 4));
    return UserCredentialRecord{
        .user_id = sqlite3_column_int64(statement, 0),
        .password_hash = password_hash != nullptr ? password_hash : "",
        .password_updated_at = password_updated_at != nullptr ? password_updated_at : "",
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

UserServiceLevelRecord read_user_service_level(sqlite3_stmt* statement) {
    const auto* service_name = reinterpret_cast<const char*>(sqlite3_column_text(statement, 2));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 6));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 7));
    return UserServiceLevelRecord{
        .id = sqlite3_column_int64(statement, 0),
        .user_id = sqlite3_column_int64(statement, 1),
        .service_name = service_name != nullptr ? service_name : "",
        .access_level = sqlite3_column_int(statement, 3),
        .enabled = sqlite3_column_int(statement, 4) != 0,
        .note = nullable_text(statement, 5),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

UserSessionRecord read_user_session(sqlite3_stmt* statement) {
    const auto* session_token_hash = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
    const auto* expires_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 3));
    const auto* last_seen_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 4));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 6));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 7));
    return UserSessionRecord{
        .id = sqlite3_column_int64(statement, 0),
        .session_token_hash = session_token_hash != nullptr ? session_token_hash : "",
        .user_id = sqlite3_column_int64(statement, 2),
        .expires_at = expires_at != nullptr ? expires_at : "",
        .last_seen_at = last_seen_at != nullptr ? last_seen_at : "",
        .revoked_at = nullable_text(statement, 5),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

template <typename T, typename Reader, typename Binder>
std::optional<T> find_one(const std::filesystem::path& database_path,
                          const char* sql,
                          Binder binder,
                          Reader reader,
                          const char* error_message) {
    SqliteConnection connection(database_path);
    Statement statement(connection.handle(), sql);
    binder(statement.get());
    const auto step_result = sqlite3_step(statement.get());
    if (step_result == SQLITE_DONE) {
        return std::nullopt;
    }
    if (step_result != SQLITE_ROW) {
        throw std::runtime_error(error_message);
    }
    return reader(statement.get());
}

}  // namespace

UserRepository::UserRepository(std::filesystem::path database_path)
    : database_path_(std::move(database_path)) {}

std::vector<UserRecord> UserRepository::list_users() const {
    static constexpr auto kSql = R"SQL(
SELECT id, username, enabled, note, created_at, updated_at
FROM users
ORDER BY id ASC;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    std::vector<UserRecord> results;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to list users");
        }
        results.push_back(read_user(statement.get()));
    }
    return results;
}

std::vector<UserServiceLevelRecord> UserRepository::list_user_service_levels() const {
    static constexpr auto kSql = R"SQL(
SELECT id, user_id, service_name, access_level, enabled, note, created_at, updated_at
FROM user_service_levels
ORDER BY user_id ASC, service_name ASC, id ASC;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    std::vector<UserServiceLevelRecord> results;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to list user service levels");
        }
        results.push_back(read_user_service_level(statement.get()));
    }
    return results;
}

std::optional<UserRecord> UserRepository::find_enabled_user_by_username(
    std::string_view username) const {
    static constexpr auto kSql = R"SQL(
SELECT id, username, enabled, note, created_at, updated_at
FROM users
WHERE username = ?1 AND enabled = 1
LIMIT 1;
)SQL";
    return find_one<UserRecord>(
        database_path_,
        kSql,
        [&](sqlite3_stmt* statement) { bind_text(statement, 1, username); },
        read_user,
        "failed to find user by username");
}

std::optional<UserRecord> UserRepository::find_enabled_user_by_id(std::int64_t user_id) const {
    static constexpr auto kSql = R"SQL(
SELECT id, username, enabled, note, created_at, updated_at
FROM users
WHERE id = ?1 AND enabled = 1
LIMIT 1;
)SQL";
    return find_one<UserRecord>(
        database_path_,
        kSql,
        [&](sqlite3_stmt* statement) { bind_int64(statement, 1, user_id); },
        read_user,
        "failed to find user by id");
}

std::optional<UserCredentialRecord> UserRepository::find_user_credential(std::int64_t user_id) const {
    static constexpr auto kSql = R"SQL(
SELECT user_id, password_hash, password_updated_at, created_at, updated_at
FROM user_credentials
WHERE user_id = ?1
LIMIT 1;
)SQL";
    return find_one<UserCredentialRecord>(
        database_path_,
        kSql,
        [&](sqlite3_stmt* statement) { bind_int64(statement, 1, user_id); },
        read_user_credential,
        "failed to find user credential");
}

std::optional<UserServiceLevelRecord> UserRepository::find_user_service_level(
    std::int64_t user_id,
    std::string_view service_name) const {
    static constexpr auto kSql = R"SQL(
SELECT id, user_id, service_name, access_level, enabled, note, created_at, updated_at
FROM user_service_levels
WHERE user_id = ?1 AND enabled = 1 AND (service_name = ?2 OR service_name = '*')
ORDER BY CASE WHEN service_name = ?2 THEN 0 ELSE 1 END, id ASC
LIMIT 1;
)SQL";
    return find_one<UserServiceLevelRecord>(
        database_path_,
        kSql,
        [&](sqlite3_stmt* statement) {
            bind_int64(statement, 1, user_id);
            bind_text(statement, 2, service_name);
        },
        read_user_service_level,
        "failed to find user service level");
}

std::optional<UserSessionRecord> UserRepository::find_active_user_session(
    std::string_view session_token_hash) const {
    static constexpr auto kSql = R"SQL(
SELECT id, session_token_hash, user_id, expires_at, last_seen_at, revoked_at, created_at, updated_at
FROM user_sessions
WHERE session_token_hash = ?1
  AND revoked_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1;
)SQL";
    return find_one<UserSessionRecord>(
        database_path_,
        kSql,
        [&](sqlite3_stmt* statement) { bind_text(statement, 1, session_token_hash); },
        read_user_session,
        "failed to find active user session");
}

std::int64_t UserRepository::insert_user_session(std::int64_t user_id,
                                                 std::string_view session_token_hash,
                                                 std::string_view expires_at) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO user_sessions (session_token_hash, user_id, expires_at)
VALUES (?1, ?2, ?3);
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, session_token_hash);
    bind_int64(statement.get(), 2, user_id);
    bind_text(statement.get(), 3, expires_at);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to insert user session");
    }
    return sqlite3_last_insert_rowid(connection.handle());
}

void UserRepository::update_user_session_last_seen(std::int64_t session_id) const {
    static constexpr auto kSql = R"SQL(
UPDATE user_sessions
SET last_seen_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?1;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, session_id);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to update user session last_seen_at");
    }
}

void UserRepository::revoke_user_session(std::string_view session_token_hash) const {
    static constexpr auto kSql = R"SQL(
UPDATE user_sessions
SET revoked_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE session_token_hash = ?1
  AND revoked_at IS NULL;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, session_token_hash);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to revoke user session");
    }
}

std::int64_t UserRepository::insert_user(const NewUserRecord& new_user_record) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO users (username, note)
VALUES (?1, ?2);
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, new_user_record.username);
    if (new_user_record.note.has_value()) {
        bind_text(statement.get(), 2, *new_user_record.note);
    } else if (sqlite3_bind_null(statement.get(), 2) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite null parameter");
    }
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to insert user");
    }
    return sqlite3_last_insert_rowid(connection.handle());
}

void UserRepository::update_user(std::int64_t user_id, const UpdateUserRecord& update_user_record) const {
    std::vector<std::string> assignments;
    if (update_user_record.note_is_set) {
        assignments.emplace_back("note = ?1");
    }
    if (update_user_record.enabled.has_value()) {
        assignments.emplace_back("enabled = ?" + std::to_string(assignments.size() + 1));
    }
    if (assignments.empty()) {
        throw std::runtime_error("update_user requires at least one changed field");
    }

    std::string sql = "UPDATE users SET ";
    for (std::size_t index = 0; index < assignments.size(); ++index) {
        if (index > 0) {
            sql += ", ";
        }
        sql += assignments[index];
    }
    sql += ", updated_at = CURRENT_TIMESTAMP WHERE id = ?" + std::to_string(assignments.size() + 1) + ";";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), sql.c_str());
    int bind_index = 1;
    if (update_user_record.note_is_set) {
        if (update_user_record.note.has_value()) {
            bind_text(statement.get(), bind_index++, *update_user_record.note);
        } else if (sqlite3_bind_null(statement.get(), bind_index++) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite null parameter");
        }
    }
    if (update_user_record.enabled.has_value()) {
        if (sqlite3_bind_int(statement.get(), bind_index++, *update_user_record.enabled ? 1 : 0) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite integer parameter");
        }
    }
    bind_int64(statement.get(), bind_index, user_id);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to update user");
    }
}

void UserRepository::delete_user(std::int64_t user_id) const {
    static constexpr auto kSql = R"SQL(
DELETE FROM users
WHERE id = ?1;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, user_id);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to delete user");
    }
}

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

void UserRepository::upsert_user_credential(std::int64_t user_id, std::string_view password_hash) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO user_credentials (user_id, password_hash, password_updated_at)
VALUES (?1, ?2, CURRENT_TIMESTAMP)
ON CONFLICT(user_id) DO UPDATE SET
    password_hash = excluded.password_hash,
    password_updated_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, user_id);
    bind_text(statement.get(), 2, password_hash);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw std::runtime_error("failed to upsert user credential");
    }
}

std::int64_t UserRepository::upsert_user_service_level(
    const NewUserServiceLevel& new_user_service_level) const {
    static constexpr auto kUpsertSql = R"SQL(
INSERT INTO user_service_levels (user_id, service_name, access_level, note)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(user_id, service_name) DO UPDATE SET
    access_level = excluded.access_level,
    note = excluded.note,
    enabled = 1,
    updated_at = CURRENT_TIMESTAMP;
)SQL";
    static constexpr auto kLookupSql = R"SQL(
SELECT id
FROM user_service_levels
WHERE user_id = ?1 AND service_name = ?2
LIMIT 1;
)SQL";

    SqliteConnection connection(database_path_);
    {
        Statement statement(connection.handle(), kUpsertSql);
        bind_int64(statement.get(), 1, new_user_service_level.user_id);
        bind_text(statement.get(), 2, new_user_service_level.service_name);
        if (sqlite3_bind_int(statement.get(), 3, new_user_service_level.access_level) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite integer parameter");
        }
        if (new_user_service_level.note.has_value()) {
            bind_text(statement.get(), 4, *new_user_service_level.note);
        } else if (sqlite3_bind_null(statement.get(), 4) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite null parameter");
        }
        if (sqlite3_step(statement.get()) != SQLITE_DONE) {
            throw std::runtime_error("failed to upsert user service level");
        }
    }

    Statement lookup(connection.handle(), kLookupSql);
    bind_int64(lookup.get(), 1, new_user_service_level.user_id);
    bind_text(lookup.get(), 2, new_user_service_level.service_name);
    if (sqlite3_step(lookup.get()) != SQLITE_ROW) {
        throw std::runtime_error("failed to locate upserted user service level");
    }
    return sqlite3_column_int64(lookup.get(), 0);
}

}  // namespace roche_limit::auth_store
