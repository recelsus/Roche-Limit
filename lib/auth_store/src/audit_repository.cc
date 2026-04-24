#include "auth_store/audit_repository.h"

#include "auth_store/sqlite_connection.h"
#include "common/debug_log.h"
#include "common/hash_util.h"
#include "sqlite_statement.h"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

namespace roche_limit::auth_store {

namespace {

constexpr int kAuditMetadataSchemaVersion = 1;

void bind_optional_int(sqlite3_stmt *statement, int index,
                       const std::optional<int> &value) {
  if (!value.has_value()) {
    if (sqlite3_bind_null(statement, index) != SQLITE_OK) {
      throw std::runtime_error("failed to bind sqlite null integer parameter");
    }
    return;
  }
  bind_int(statement, index, *value);
}

bool env_bool_enabled(const char *name) {
  const char *value = std::getenv(name);
  if (value == nullptr) {
    return false;
  }
  return std::string(value) == "1";
}

std::string escape_json_string(std::string_view value) {
  std::ostringstream stream;
  for (const char ch : value) {
    switch (ch) {
    case '\\':
      stream << "\\\\";
      break;
    case '"':
      stream << "\\\"";
      break;
    case '\b':
      stream << "\\b";
      break;
    case '\f':
      stream << "\\f";
      break;
    case '\n':
      stream << "\\n";
      break;
    case '\r':
      stream << "\\r";
      break;
    case '\t':
      stream << "\\t";
      break;
    default:
      if (static_cast<unsigned char>(ch) < 0x20) {
        stream << "\\u00";
        static constexpr char kHex[] = "0123456789abcdef";
        stream << kHex[(ch >> 4) & 0x0f] << kHex[ch & 0x0f];
      } else {
        stream << ch;
      }
      break;
    }
  }
  return stream.str();
}

void append_optional_json_string_field(std::ostringstream &stream, bool &first,
                                       std::string_view name,
                                       const std::optional<std::string> &value) {
  if (!value.has_value()) {
    return;
  }
  if (!first) {
    stream << ',';
  }
  first = false;
  stream << '"' << name << "\":\"" << escape_json_string(*value) << '"';
}

void append_json_string_field(std::ostringstream &stream, bool &first,
                              std::string_view name, std::string_view value) {
  if (!first) {
    stream << ',';
  }
  first = false;
  stream << '"' << name << "\":\"" << escape_json_string(value) << '"';
}

void append_json_int_field(std::ostringstream &stream, bool &first,
                           std::string_view name,
                           const std::optional<int> &value) {
  if (!value.has_value()) {
    return;
  }
  if (!first) {
    stream << ',';
  }
  first = false;
  stream << '"' << name << "\":" << *value;
}

std::string derive_event_group(std::string_view event_type) {
  const auto underscore = event_type.find('_');
  if (underscore == std::string_view::npos) {
    return std::string(event_type);
  }
  return std::string(event_type.substr(0, underscore));
}

std::string normalized_metadata_json(const NewAuditEvent &event) {
  std::ostringstream stream;
  stream << '{';
  bool first = true;
  stream << "\"schema_version\":" << kAuditMetadataSchemaVersion;
  first = false;
  append_json_string_field(stream, first, "source", "roche-limit");
  append_json_string_field(stream, first, "event_group",
                           derive_event_group(event.event_type));
  append_json_string_field(stream, first, "event_type", event.event_type);
  append_json_string_field(stream, first, "actor_type", event.actor_type);
  append_optional_json_string_field(stream, first, "actor_id", event.actor_id);
  append_optional_json_string_field(stream, first, "target_type",
                                    event.target_type);
  append_optional_json_string_field(stream, first, "target_id",
                                    event.target_id);
  append_optional_json_string_field(stream, first, "service_name",
                                    event.service_name);
  append_json_int_field(stream, first, "access_level", event.access_level);
  append_optional_json_string_field(stream, first, "client_ip",
                                    event.client_ip);
  append_optional_json_string_field(stream, first, "request_id",
                                    event.request_id);
  append_json_string_field(stream, first, "result", event.result);
  append_optional_json_string_field(stream, first, "reason", event.reason);
  if (!first) {
    stream << ',';
  }
  stream << "\"details\":";
  if (event.metadata_json.has_value() && !event.metadata_json->empty()) {
    stream << *event.metadata_json;
  } else {
    stream << "{}";
  }
  stream << '}';
  return stream.str();
}

std::optional<std::string> latest_event_hash(sqlite3 *db) {
  static constexpr auto kSql =
      "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;";
  Statement statement(db, kSql);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result == SQLITE_DONE) {
    return std::nullopt;
  }
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to read latest audit event hash");
  }
  const auto *value =
      reinterpret_cast<const char *>(sqlite3_column_text(statement.get(), 0));
  if (value == nullptr || *value == '\0') {
    return std::nullopt;
  }
  return std::string(value);
}

std::string canonical_hash_input(const NewAuditEvent &event,
                                 std::string_view metadata_json,
                                 const std::optional<std::string> &prev_hash) {
  std::ostringstream stream;
  stream << "prev_hash=" << (prev_hash.has_value() ? *prev_hash : "ROOT")
         << '\n'
         << "event_type=" << event.event_type << '\n'
         << "actor_type=" << event.actor_type << '\n'
         << "actor_id=" << event.actor_id.value_or("") << '\n'
         << "target_type=" << event.target_type.value_or("") << '\n'
         << "target_id=" << event.target_id.value_or("") << '\n'
         << "service_name=" << event.service_name.value_or("") << '\n'
         << "access_level="
         << (event.access_level.has_value()
                 ? std::to_string(*event.access_level)
                 : "")
         << '\n'
         << "client_ip=" << event.client_ip.value_or("") << '\n'
         << "request_id=" << event.request_id.value_or("") << '\n'
         << "result=" << event.result << '\n'
         << "reason=" << event.reason.value_or("") << '\n'
         << "metadata_json=" << metadata_json;
  return stream.str();
}

int execute_delete_and_changes(sqlite3 *db, const char *sql,
                               const std::function<void(sqlite3_stmt *)>
                                   &binder) {
  Statement statement(db, sql);
  binder(statement.get());
  step_done_or_throw(statement.get(), "failed to delete audit events");
  return sqlite3_changes(db);
}

int scalar_int(sqlite3 *db, const char *sql) {
  Statement statement(db, sql);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to read audit scalar value");
  }
  return sqlite3_column_int(statement.get(), 0);
}

} // namespace

AuditRepository::AuditRepository(std::filesystem::path database_path)
    : database_path_(std::move(database_path)) {}

void AuditRepository::insert_event(const NewAuditEvent &event) const {
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[audit] insert begin this=" << static_cast<const void *>(this)
              << " db=" << database_path_.string()
              << " event_type=" << event.event_type
              << " actor_type=" << event.actor_type
              << " result=" << event.result << std::endl;
  }
  static constexpr auto kSql = R"SQL(
INSERT INTO audit_events (
    event_type,
    actor_type,
    actor_id,
    target_type,
    target_id,
    service_name,
    access_level,
    client_ip,
    request_id,
    result,
    reason,
    metadata_json,
    prev_event_hash,
    event_hash
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14);
)SQL";

  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[audit] opening sqlite connection" << std::endl;
  }
  SqliteConnection connection(database_path_);
  const auto metadata_json = normalized_metadata_json(event);
  const auto prev_hash = latest_event_hash(connection.handle());
  const auto event_hash = roche_limit::common::sha256_hex(
      canonical_hash_input(event, metadata_json, prev_hash));

  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[audit] preparing statement" << std::endl;
  }
  Statement statement(connection.handle(), kSql);
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[audit] binding values" << std::endl;
  }
  bind_text(statement.get(), 1, event.event_type);
  bind_text(statement.get(), 2, event.actor_type);
  bind_nullable_text(statement.get(), 3, event.actor_id);
  bind_nullable_text(statement.get(), 4, event.target_type);
  bind_nullable_text(statement.get(), 5, event.target_id);
  bind_nullable_text(statement.get(), 6, event.service_name);
  bind_optional_int(statement.get(), 7, event.access_level);
  bind_nullable_text(statement.get(), 8, event.client_ip);
  bind_nullable_text(statement.get(), 9, event.request_id);
  bind_text(statement.get(), 10, event.result);
  bind_nullable_text(statement.get(), 11, event.reason);
  bind_text(statement.get(), 12, metadata_json);
  bind_nullable_text(statement.get(), 13, prev_hash);
  bind_text(statement.get(), 14, event_hash);
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[audit] stepping insert" << std::endl;
  }
  step_done_or_throw(statement.get(), "failed to insert audit event");
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[audit] insert done" << std::endl;
  }
}

AuditCleanupResult AuditRepository::cleanup(int retention_days,
                                            int max_rows) const {
  SqliteConnection connection(database_path_);
  const int retention_deleted_rows = execute_delete_and_changes(
      connection.handle(),
      R"SQL(
DELETE FROM audit_events
WHERE created_at < datetime('now', ?1);
)SQL",
      [retention_days](sqlite3_stmt *statement) {
        bind_text(statement, 1,
                  "-" + std::to_string(retention_days) + " days");
      });

  const int current_rows = scalar_int(connection.handle(),
                                      "SELECT COUNT(*) FROM audit_events;");
  const int overflow_deleted_rows =
      std::max(0, current_rows + 1 - std::max(max_rows, 1));
  if (overflow_deleted_rows > 0) {
    execute_delete_and_changes(
        connection.handle(),
        R"SQL(
DELETE FROM audit_events
WHERE id IN (
    SELECT id FROM audit_events ORDER BY id ASC LIMIT ?1
);
)SQL",
        [overflow_deleted_rows](sqlite3_stmt *statement) {
          bind_int(statement, 1, overflow_deleted_rows);
        });
  }

  insert_event(NewAuditEvent{
      .event_type = "audit_cleanup",
      .actor_type = "system",
      .result = "success",
      .metadata_json =
          std::string("{\"retention_days\":") + std::to_string(retention_days) +
          ",\"max_rows\":" + std::to_string(max_rows) +
          ",\"retention_deleted_rows\":" +
          std::to_string(retention_deleted_rows) +
          ",\"overflow_deleted_rows\":" +
          std::to_string(overflow_deleted_rows) + "}"});

  return AuditCleanupResult{
      .retention_deleted_rows = retention_deleted_rows,
      .overflow_deleted_rows = overflow_deleted_rows,
  };
}

bool audit_auth_allow_enabled() {
  return env_bool_enabled("ROCHE_LIMIT_AUDIT_AUTH_ALLOW");
}

} // namespace roche_limit::auth_store
