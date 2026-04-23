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

}  // namespace

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
    step_done_or_throw(statement.get(), "failed to insert user session");
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

}  // namespace roche_limit::auth_store
