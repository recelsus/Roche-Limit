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

ApiKeyRecord read_api_key(sqlite3_stmt *statement) {
  const auto *key_hash =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 1));
  const auto *key_lookup_hash =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 2));
  const auto *created_at =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 13));
  const auto *updated_at =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 14));

  return ApiKeyRecord{
      .id = sqlite3_column_int64(statement, 0),
      .key_hash = key_hash != nullptr ? key_hash : "",
      .key_lookup_hash = key_lookup_hash != nullptr ? key_lookup_hash : "",
      .key_prefix = nullable_text(statement, 3),
      .service_name = nullable_text(statement, 4),
      .access_level = sqlite3_column_int(statement, 5),
      .enabled = sqlite3_column_int(statement, 6) != 0,
      .expires_at = nullable_text(statement, 7),
      .last_used_at = nullable_text(statement, 8),
      .last_used_ip = nullable_text(statement, 9),
      .last_failed_at = nullable_text(statement, 10),
      .failed_attempts = sqlite3_column_int(statement, 11),
      .note = nullable_text(statement, 12),
      .created_at = created_at != nullptr ? created_at : "",
      .updated_at = updated_at != nullptr ? updated_at : "",
  };
}

void disable_expired_api_keys_on_connection(sqlite3 *db) {
  static constexpr auto kSql = R"SQL(
UPDATE api_keys
SET enabled = 0, updated_at = CURRENT_TIMESTAMP
WHERE enabled = 1
  AND expires_at IS NOT NULL
  AND expires_at <= CURRENT_TIMESTAMP;
)SQL";
  Statement statement(db, kSql);
  step_done_or_throw(statement.get(), "failed to disable expired api keys");
}

std::optional<ApiKeyRecord> query_single_api_key(sqlite3 *db, const char *sql,
                                                 std::string_view first,
                                                 std::string_view second) {
  Statement statement(db, sql);
  bind_text(statement.get(), 1, first);
  bind_text(statement.get(), 2, second);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result == SQLITE_DONE) {
    return std::nullopt;
  }
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to fetch api key");
  }
  return read_api_key(statement.get());
}

std::optional<ApiKeyRecord> query_single_api_key(sqlite3 *db, const char *sql,
                                                 std::int64_t api_key_id) {
  Statement statement(db, sql);
  bind_int64(statement.get(), 1, api_key_id);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result == SQLITE_DONE) {
    return std::nullopt;
  }
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to fetch api key");
  }
  return read_api_key(statement.get());
}

} // namespace

std::optional<ApiKeyRecord>
RuleRepository::find_api_key(std::string_view key_lookup_hash,
                             std::string_view service_name) const {
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[auth_store] find_api_key begin service=" << service_name
              << std::endl;
  }
  static constexpr auto kSql = R"SQL(
SELECT id, key_hash, key_lookup_hash, key_prefix, service_name, access_level, enabled, expires_at,
       last_used_at, last_used_ip, last_failed_at, failed_attempts, note, created_at, updated_at
FROM api_keys
WHERE key_lookup_hash = ?1
  AND enabled = 1
  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
  AND (service_name = ?2 OR service_name IS NULL)
ORDER BY CASE WHEN service_name = ?2 THEN 0 ELSE 1 END, id ASC
LIMIT 1;
)SQL";

  SqliteConnection connection(database_path_);
  disable_expired_api_keys_on_connection(connection.handle());
  const auto result =
      query_single_api_key(connection.handle(), kSql, key_lookup_hash,
                           service_name);
  if (!result.has_value()) {
    if (roche_limit::common::verbose_logging_enabled()) {
      std::cerr << "[auth_store] find_api_key no match" << std::endl;
    }
    return std::nullopt;
  }

  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[auth_store] find_api_key matched" << std::endl;
  }
  return result;
}

std::optional<ApiKeyRecord>
RuleRepository::find_api_key_by_prefix(std::string_view key_prefix,
                                       std::string_view service_name) const {
  static constexpr auto kSql = R"SQL(
SELECT id, key_hash, key_lookup_hash, key_prefix, service_name, access_level, enabled, expires_at,
       last_used_at, last_used_ip, last_failed_at, failed_attempts, note, created_at, updated_at
FROM api_keys
WHERE key_prefix = ?1
  AND enabled = 1
  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
  AND (service_name = ?2 OR service_name IS NULL)
ORDER BY CASE WHEN service_name = ?2 THEN 0 ELSE 1 END, id ASC
LIMIT 1;
)SQL";

  SqliteConnection connection(database_path_);
  disable_expired_api_keys_on_connection(connection.handle());
  return query_single_api_key(connection.handle(), kSql, key_prefix,
                              service_name);
}

std::vector<ApiKeyRecord> RuleRepository::list_api_keys() const {
  static constexpr auto kSql = R"SQL(
SELECT id, key_hash, key_lookup_hash, key_prefix, service_name, access_level, enabled, expires_at,
       last_used_at, last_used_ip, last_failed_at, failed_attempts, note, created_at, updated_at
FROM api_keys
ORDER BY key_prefix ASC, service_name ASC, id ASC;
)SQL";

  SqliteConnection connection(database_path_);
  disable_expired_api_keys_on_connection(connection.handle());
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

std::optional<ApiKeyRecord> RuleRepository::get_api_key(
    std::int64_t api_key_id) const {
  static constexpr auto kSql = R"SQL(
SELECT id, key_hash, key_lookup_hash, key_prefix, service_name, access_level, enabled, expires_at,
       last_used_at, last_used_ip, last_failed_at, failed_attempts, note, created_at, updated_at
FROM api_keys
WHERE id = ?1
LIMIT 1;
)SQL";

  SqliteConnection connection(database_path_);
  disable_expired_api_keys_on_connection(connection.handle());
  return query_single_api_key(connection.handle(), kSql, api_key_id);
}

std::int64_t RuleRepository::insert_api_key(
    const NewApiKeyRecord &new_api_key_record) const {
  static constexpr auto kSql = R"SQL(
INSERT INTO api_keys (
    key_hash,
    key_lookup_hash,
    key_prefix,
    service_name,
    access_level,
    expires_at,
    note
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
)SQL";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_text(statement.get(), 1, new_api_key_record.key_hash);
  bind_text(statement.get(), 2, new_api_key_record.key_lookup_hash);
  bind_nullable_text(statement.get(), 3, new_api_key_record.key_prefix);
  bind_nullable_text(statement.get(), 4, new_api_key_record.service_name);
  bind_int(statement.get(), 5, new_api_key_record.access_level);
  bind_nullable_text(statement.get(), 6, new_api_key_record.expires_at);
  bind_nullable_text(statement.get(), 7, new_api_key_record.note);
  step_done_or_throw(statement.get(), "failed to insert api key");

  return sqlite3_last_insert_rowid(connection.handle());
}

void RuleRepository::update_api_key(
    std::int64_t api_key_id,
    const UpdateApiKeyRecord &update_api_key_record) const {
  std::vector<std::string> assignments;
  if (update_api_key_record.service_name_is_set) {
    assignments.emplace_back("service_name = ?" +
                             std::to_string(assignments.size() + 1));
  }
  if (update_api_key_record.access_level.has_value()) {
    assignments.emplace_back("access_level = ?" +
                             std::to_string(assignments.size() + 1));
  }
  if (update_api_key_record.expires_at_is_set) {
    assignments.emplace_back("expires_at = ?" +
                             std::to_string(assignments.size() + 1));
  }
  if (update_api_key_record.note_is_set) {
    assignments.emplace_back("note = ?" +
                             std::to_string(assignments.size() + 1));
  }
  if (assignments.empty()) {
    throw std::runtime_error(
        "update_api_key requires at least one changed field");
  }

  std::string sql = "UPDATE api_keys SET ";
  for (std::size_t index = 0; index < assignments.size(); ++index) {
    if (index > 0) {
      sql += ", ";
    }
    sql += assignments[index];
  }
  sql += ", updated_at = CURRENT_TIMESTAMP WHERE id = ?" +
         std::to_string(assignments.size() + 1) + ";";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), sql.c_str());

  int bind_index = 1;
  if (update_api_key_record.service_name_is_set) {
    bind_nullable_text(statement.get(), bind_index++,
                       update_api_key_record.service_name);
  }
  if (update_api_key_record.access_level.has_value()) {
    bind_int(statement.get(), bind_index++,
             *update_api_key_record.access_level);
  }
  if (update_api_key_record.expires_at_is_set) {
    bind_nullable_text(statement.get(), bind_index++,
                       update_api_key_record.expires_at);
  }
  if (update_api_key_record.note_is_set) {
    bind_nullable_text(statement.get(), bind_index++,
                       update_api_key_record.note);
  }
  bind_int64(statement.get(), bind_index, api_key_id);
  step_done_or_throw(statement.get(), "failed to update api key");
}

void RuleRepository::disable_api_key(std::int64_t api_key_id) const {
  static constexpr auto kSql = "UPDATE api_keys SET enabled = 0, updated_at = "
                               "CURRENT_TIMESTAMP WHERE id = ?1;";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1, api_key_id);
  step_done_or_throw(statement.get(), "failed to disable api key");
}

void RuleRepository::disable_expired_api_keys() const {
  SqliteConnection connection(database_path_);
  disable_expired_api_keys_on_connection(connection.handle());
}

void RuleRepository::note_api_key_success(std::int64_t api_key_id,
                                          std::string_view client_ip) const {
  static constexpr auto kSql = R"SQL(
UPDATE api_keys
SET last_used_at = CURRENT_TIMESTAMP,
    last_used_ip = ?2,
    failed_attempts = 0,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?1;
)SQL";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1, api_key_id);
  bind_text(statement.get(), 2, client_ip);
  step_done_or_throw(statement.get(), "failed to record api key success");
}

void RuleRepository::note_api_key_failure(std::int64_t api_key_id,
                                          std::string_view client_ip) const {
  static constexpr auto kSql = R"SQL(
UPDATE api_keys
SET last_failed_at = CURRENT_TIMESTAMP,
    last_used_ip = ?2,
    failed_attempts = failed_attempts + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?1;
)SQL";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1, api_key_id);
  bind_text(statement.get(), 2, client_ip);
  step_done_or_throw(statement.get(), "failed to record api key failure");
}

void RuleRepository::delete_api_key(std::int64_t api_key_id) const {
  static constexpr auto kSql = "DELETE FROM api_keys WHERE id = ?1;";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1, api_key_id);
  step_done_or_throw(statement.get(), "failed to delete api key");
}

} // namespace roche_limit::auth_store
