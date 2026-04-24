#include "auth_store/user_repository.h"

#include "auth_store/sqlite_connection.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

#include <stdexcept>

namespace roche_limit::auth_store {

namespace {

using roche_limit::auth_core::LoginFailureRecord;

LoginFailureRecord read_login_failure(sqlite3_stmt* statement) {
    const auto* client_ip =
        reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
    const auto* username =
        reinterpret_cast<const char*>(sqlite3_column_text(statement, 2));
    const auto* last_failed_at =
        reinterpret_cast<const char*>(sqlite3_column_text(statement, 4));
    const auto* created_at =
        reinterpret_cast<const char*>(sqlite3_column_text(statement, 6));
    const auto* updated_at =
        reinterpret_cast<const char*>(sqlite3_column_text(statement, 7));
    return LoginFailureRecord{
        .id = sqlite3_column_int64(statement, 0),
        .client_ip = client_ip != nullptr ? client_ip : "",
        .username = username != nullptr ? username : "",
        .failure_count = sqlite3_column_int(statement, 3),
        .last_failed_at = last_failed_at != nullptr ? last_failed_at : "",
        .locked_until = nullable_text(statement, 5),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

}  // namespace

std::optional<LoginFailureRecord> UserRepository::find_login_failure(
    std::string_view client_ip, std::string_view username) const {
    static constexpr auto kSql = R"SQL(
SELECT id, client_ip, username, failure_count, last_failed_at, locked_until, created_at, updated_at
FROM login_failures
WHERE client_ip = ?1 AND username = ?2
LIMIT 1;
)SQL";
    return find_one<LoginFailureRecord>(
        database_path_,
        kSql,
        [&](sqlite3_stmt* statement) {
            bind_text(statement, 1, client_ip);
            bind_text(statement, 2, username);
        },
        read_login_failure,
        "failed to find login failure");
}

void UserRepository::upsert_login_failure(
    std::string_view client_ip, std::string_view username, int failure_count,
    std::optional<std::string_view> locked_until) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO login_failures (client_ip, username, failure_count, last_failed_at, locked_until)
VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, ?4)
ON CONFLICT(client_ip, username) DO UPDATE SET
    failure_count = excluded.failure_count,
    last_failed_at = CURRENT_TIMESTAMP,
    locked_until = excluded.locked_until,
    updated_at = CURRENT_TIMESTAMP;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, client_ip);
    bind_text(statement.get(), 2, username);
    if (sqlite3_bind_int(statement.get(), 3, failure_count) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
    if (locked_until.has_value()) {
        bind_text(statement.get(), 4, *locked_until);
    } else if (sqlite3_bind_null(statement.get(), 4) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite null parameter");
    }
    step_done_or_throw(statement.get(), "failed to upsert login failure");
}

void UserRepository::clear_login_failure(std::string_view client_ip,
                                         std::string_view username) const {
    static constexpr auto kSql = R"SQL(
DELETE FROM login_failures
WHERE client_ip = ?1 AND username = ?2;
)SQL";
    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, client_ip);
    bind_text(statement.get(), 2, username);
    step_done_or_throw(statement.get(), "failed to clear login failure");
}

}  // namespace roche_limit::auth_store
