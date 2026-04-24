#include "auth_store/user_repository.h"

#include "auth_store/sqlite_connection.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

namespace roche_limit::auth_store {

void UserRepository::insert_csrf_token(std::string_view purpose,
                                       std::string_view token_hash,
                                       std::string_view client_ip,
                                       std::string_view expires_at) const {
    static constexpr auto kCleanupSql = R"SQL(
DELETE FROM csrf_tokens
WHERE expires_at <= CURRENT_TIMESTAMP;
)SQL";
    static constexpr auto kInsertSql = R"SQL(
INSERT INTO csrf_tokens (purpose, token_hash, client_ip, expires_at)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(token_hash) DO UPDATE SET
    purpose = excluded.purpose,
    client_ip = excluded.client_ip,
    expires_at = excluded.expires_at,
    updated_at = CURRENT_TIMESTAMP;
)SQL";
    SqliteConnection connection(database_path_);
    connection.execute(kCleanupSql);
    Statement statement(connection.handle(), kInsertSql);
    bind_text(statement.get(), 1, purpose);
    bind_text(statement.get(), 2, token_hash);
    bind_text(statement.get(), 3, client_ip);
    bind_text(statement.get(), 4, expires_at);
    step_done_or_throw(statement.get(), "failed to insert csrf token");
}

bool UserRepository::has_valid_csrf_token(std::string_view purpose,
                                          std::string_view token_hash,
                                          std::string_view client_ip) const {
    static constexpr auto kSql = R"SQL(
SELECT 1
FROM csrf_tokens
WHERE purpose = ?1
  AND token_hash = ?2
  AND client_ip = ?3
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1;
)SQL";
    return find_one<int>(
               database_path_,
               kSql,
               [&](sqlite3_stmt* statement) {
                   bind_text(statement, 1, purpose);
                   bind_text(statement, 2, token_hash);
                   bind_text(statement, 3, client_ip);
               },
               [](sqlite3_stmt* statement) { return sqlite3_column_int(statement, 0); },
               "failed to validate csrf token")
        .has_value();
}

}  // namespace roche_limit::auth_store
