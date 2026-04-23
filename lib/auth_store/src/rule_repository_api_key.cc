#include "auth_store/rule_repository.h"

#include "auth_store/sqlite_connection.h"
#include "common/debug_log.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace roche_limit::auth_store {

namespace {

using roche_limit::auth_core::ApiKeyRecord;

ApiKeyRecord read_api_key(sqlite3_stmt* statement) {
    const auto* key_hash = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 8));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 9));

    return ApiKeyRecord{
        .id = sqlite3_column_int64(statement, 0),
        .key_hash = key_hash != nullptr ? key_hash : "",
        .key_prefix = nullable_text(statement, 2),
        .service_name = nullable_text(statement, 3),
        .access_level = sqlite3_column_int(statement, 4),
        .enabled = sqlite3_column_int(statement, 5) != 0,
        .expires_at = nullable_text(statement, 6),
        .note = nullable_text(statement, 7),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

}  // namespace

std::optional<ApiKeyRecord> RuleRepository::find_api_key(
    std::string_view key_hash,
    std::string_view service_name) const {
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_store] find_api_key begin service=" << service_name << std::endl;
    }
    static constexpr auto kSql = R"SQL(
SELECT id, key_hash, key_prefix, service_name, access_level, enabled, expires_at, note, created_at, updated_at
FROM api_keys
WHERE key_hash = ?1
  AND enabled = 1
  AND (service_name = ?2 OR service_name IS NULL)
ORDER BY CASE WHEN service_name = ?2 THEN 0 ELSE 1 END, id ASC
LIMIT 1;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, key_hash);
    bind_text(statement.get(), 2, service_name);

    const auto step_result = sqlite3_step(statement.get());
    if (step_result == SQLITE_DONE) {
        if (roche_limit::common::verbose_logging_enabled()) {
            std::cerr << "[auth_store] find_api_key no match" << std::endl;
        }
        return std::nullopt;
    }
    if (step_result != SQLITE_ROW) {
        throw std::runtime_error("failed to fetch api key");
    }

    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_store] find_api_key matched" << std::endl;
    }
    return read_api_key(statement.get());
}

std::vector<ApiKeyRecord> RuleRepository::list_api_keys() const {
    static constexpr auto kSql = R"SQL(
SELECT id, key_hash, key_prefix, service_name, access_level, enabled, expires_at, note, created_at, updated_at
FROM api_keys
ORDER BY key_hash ASC, service_name ASC, id ASC;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);

    std::vector<ApiKeyRecord> results;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to list api keys");
        }
        results.push_back(read_api_key(statement.get()));
    }

    return results;
}

std::int64_t RuleRepository::insert_api_key(const NewApiKeyRecord& new_api_key_record) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO api_keys (
    key_hash,
    key_prefix,
    service_name,
    access_level,
    expires_at,
    note
) VALUES (?1, ?2, ?3, ?4, ?5, ?6);
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, new_api_key_record.key_hash);
    bind_nullable_text(statement.get(), 2, new_api_key_record.key_prefix);
    bind_nullable_text(statement.get(), 3, new_api_key_record.service_name);
    bind_int(statement.get(), 4, new_api_key_record.access_level);
    bind_nullable_text(statement.get(), 5, new_api_key_record.expires_at);
    bind_nullable_text(statement.get(), 6, new_api_key_record.note);
    step_done_or_throw(statement.get(), "failed to insert api key");

    return sqlite3_last_insert_rowid(connection.handle());
}

void RuleRepository::update_api_key(std::int64_t api_key_id,
                                    const UpdateApiKeyRecord& update_api_key_record) const {
    std::vector<std::string> assignments;
    if (update_api_key_record.service_name_is_set) {
        assignments.emplace_back("service_name = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_api_key_record.access_level.has_value()) {
        assignments.emplace_back("access_level = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_api_key_record.expires_at_is_set) {
        assignments.emplace_back("expires_at = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_api_key_record.note_is_set) {
        assignments.emplace_back("note = ?" + std::to_string(assignments.size() + 1));
    }
    if (assignments.empty()) {
        throw std::runtime_error("update_api_key requires at least one changed field");
    }

    std::string sql = "UPDATE api_keys SET ";
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
    if (update_api_key_record.service_name_is_set) {
        bind_nullable_text(statement.get(), bind_index++, update_api_key_record.service_name);
    }
    if (update_api_key_record.access_level.has_value()) {
        bind_int(statement.get(), bind_index++, *update_api_key_record.access_level);
    }
    if (update_api_key_record.expires_at_is_set) {
        bind_nullable_text(statement.get(), bind_index++, update_api_key_record.expires_at);
    }
    if (update_api_key_record.note_is_set) {
        bind_nullable_text(statement.get(), bind_index++, update_api_key_record.note);
    }
    bind_int64(statement.get(), bind_index, api_key_id);
    step_done_or_throw(statement.get(), "failed to update api key");
}

void RuleRepository::disable_api_key(std::int64_t api_key_id) const {
    static constexpr auto kSql =
        "UPDATE api_keys SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?1;";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, api_key_id);
    step_done_or_throw(statement.get(), "failed to disable api key");
}

void RuleRepository::delete_api_key(std::int64_t api_key_id) const {
    static constexpr auto kSql = "DELETE FROM api_keys WHERE id = ?1;";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, api_key_id);
    step_done_or_throw(statement.get(), "failed to delete api key");
}

}  // namespace roche_limit::auth_store
