#include "auth_store/user_repository.h"

#include "auth_store/sqlite_connection.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

#include <stdexcept>
#include <string_view>

namespace roche_limit::auth_store {

namespace {

using roche_limit::auth_core::UserSessionRecord;

UserSessionRecord read_user_session(sqlite3_stmt* statement) {
    const auto* session_token_hash = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
    const auto* absolute_expires_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 3));
    const auto* idle_expires_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 4));
    const auto* last_seen_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 5));
    const auto* last_rotated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 6));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 8));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 9));
    return UserSessionRecord{
        .id = sqlite3_column_int64(statement, 0),
        .session_token_hash = session_token_hash != nullptr ? session_token_hash : "",
        .user_id = sqlite3_column_int64(statement, 2),
        .absolute_expires_at = absolute_expires_at != nullptr ? absolute_expires_at : "",
        .idle_expires_at = idle_expires_at != nullptr ? idle_expires_at : "",
        .last_seen_at = last_seen_at != nullptr ? last_seen_at : "",
        .last_rotated_at = last_rotated_at != nullptr ? last_rotated_at : "",
        .revoked_at = nullable_text(statement, 7),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

}  // namespace

std::optional<UserSessionRecord> UserRepository::find_active_user_session(
    std::string_view session_token_hash) const {
    static constexpr auto kSql = R"SQL(
SELECT id, session_token_hash, user_id, absolute_expires_at, idle_expires_at, last_seen_at, last_rotated_at, revoked_at, created_at, updated_at
FROM user_sessions
WHERE session_token_hash = ?1
  AND revoked_at IS NULL
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
                                                 std::string_view absolute_expires_at,
                                                 std::string_view idle_expires_at,
                                                 std::string_view last_rotated_at) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO user_sessions (
    session_token_hash,
    user_id,
    absolute_expires_at,
    idle_expires_at,
    last_rotated_at
)
VALUES (?1, ?2, ?3, ?4, ?5);
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, session_token_hash);
    bind_int64(statement.get(), 2, user_id);
    bind_text(statement.get(), 3, absolute_expires_at);
    bind_text(statement.get(), 4, idle_expires_at);
    bind_text(statement.get(), 5, last_rotated_at);
    step_done_or_throw(statement.get(), "failed to insert user session");
    return sqlite3_last_insert_rowid(connection.handle());
}

void UserRepository::update_user_session_activity(std::int64_t session_id,
                                                  std::string_view idle_expires_at) const {
    static constexpr auto kSql = R"SQL(
UPDATE user_sessions
SET last_seen_at = CURRENT_TIMESTAMP,
    idle_expires_at = ?2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?1;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, session_id);
    bind_text(statement.get(), 2, idle_expires_at);
    step_done_or_throw(statement.get(), "failed to update user session last_seen_at");
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
    step_done_or_throw(statement.get(), "failed to revoke user session");
}

void UserRepository::revoke_user_session_by_id(std::int64_t session_id) const {
    static constexpr auto kSql = R"SQL(
UPDATE user_sessions
SET revoked_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?1
  AND revoked_at IS NULL;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, session_id);
    step_done_or_throw(statement.get(), "failed to revoke user session by id");
}

void UserRepository::revoke_all_user_sessions(std::int64_t user_id) const {
    static constexpr auto kSql = R"SQL(
UPDATE user_sessions
SET revoked_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = ?1
  AND revoked_at IS NULL;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, user_id);
    step_done_or_throw(statement.get(), "failed to revoke all user sessions");
}

std::vector<UserSessionRecord> UserRepository::list_user_sessions(
    std::optional<std::int64_t> user_id) const {
    const auto sql = user_id.has_value()
                         ? std::string(R"SQL(
SELECT id, session_token_hash, user_id, absolute_expires_at, idle_expires_at, last_seen_at, last_rotated_at, revoked_at, created_at, updated_at
FROM user_sessions
WHERE user_id = ?1
ORDER BY id ASC;
)SQL")
                         : std::string(R"SQL(
SELECT id, session_token_hash, user_id, absolute_expires_at, idle_expires_at, last_seen_at, last_rotated_at, revoked_at, created_at, updated_at
FROM user_sessions
ORDER BY id ASC;
)SQL");
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), sql.c_str());
    if (user_id.has_value()) {
        bind_int64(statement.get(), 1, *user_id);
    }
    std::vector<UserSessionRecord> sessions;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to list user sessions");
        }
        sessions.push_back(read_user_session(statement.get()));
    }
    return sessions;
}

}  // namespace roche_limit::auth_store
