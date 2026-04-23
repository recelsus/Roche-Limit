#include "auth_store/audit_repository.h"

#include "auth_store/sqlite_connection.h"
#include "sqlite_statement.h"

#include <cstdlib>
#include <stdexcept>
#include <string>

namespace roche_limit::auth_store {

namespace {

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

} // namespace

AuditRepository::AuditRepository(std::filesystem::path database_path)
    : database_path_(std::move(database_path)) {}

void AuditRepository::insert_event(const NewAuditEvent &event) const {
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
    metadata_json
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);
)SQL";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
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
  bind_nullable_text(statement.get(), 12, event.metadata_json);
  step_done_or_throw(statement.get(), "failed to insert audit event");
}

void AuditRepository::cleanup(int retention_days, int max_rows) const {
  SqliteConnection connection(database_path_);
  {
    static constexpr auto kSql = R"SQL(
DELETE FROM audit_events
WHERE created_at < datetime('now', ?1);
)SQL";
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1,
              "-" + std::to_string(retention_days) + " days");
    step_done_or_throw(statement.get(), "failed to cleanup old audit events");
  }
  insert_event(NewAuditEvent{
      .event_type = "audit_cleanup",
      .actor_type = "system",
      .result = "success",
  });
  {
    static constexpr auto kSql = R"SQL(
DELETE FROM audit_events
WHERE id NOT IN (
    SELECT id FROM audit_events ORDER BY id DESC LIMIT ?1
);
)SQL";
    Statement statement(connection.handle(), kSql);
    bind_int(statement.get(), 1, max_rows);
    step_done_or_throw(statement.get(),
                       "failed to enforce audit event max rows");
  }
}

bool audit_auth_allow_enabled() {
  return env_bool_enabled("ROCHE_LIMIT_AUDIT_AUTH_ALLOW");
}

} // namespace roche_limit::auth_store
