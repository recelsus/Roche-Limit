#include "auth_store/rule_repository.h"

#include "auth_store/sqlite_connection.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace roche_limit::auth_store {

namespace {

using roche_limit::auth_core::ClientCertRecord;
using roche_limit::auth_core::ClientCertServiceLevelRecord;

ClientCertRecord read_client_cert(sqlite3_stmt *statement) {
  const auto *fingerprint =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 1));
  const auto *created_at =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 12));
  const auto *updated_at =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 13));
  return ClientCertRecord{
      .id = sqlite3_column_int64(statement, 0),
      .fingerprint_sha256 = fingerprint != nullptr ? fingerprint : "",
      .serial_number = nullable_text(statement, 2),
      .subject_dn = nullable_text(statement, 3),
      .issuer_dn = nullable_text(statement, 4),
      .enabled = sqlite3_column_int(statement, 5) != 0,
      .not_before = nullable_text(statement, 6),
      .not_after = nullable_text(statement, 7),
      .last_used_at = nullable_text(statement, 8),
      .last_used_ip = nullable_text(statement, 9),
      .note = nullable_text(statement, 10),
      .created_at = created_at != nullptr ? created_at : "",
      .updated_at = updated_at != nullptr ? updated_at : "",
      .revoked_at = nullable_text(statement, 14),
  };
}

ClientCertServiceLevelRecord
read_client_cert_service_level(sqlite3_stmt *statement) {
  const auto *service_name =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 2));
  const auto *created_at =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 6));
  const auto *updated_at =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 7));
  return ClientCertServiceLevelRecord{
      .id = sqlite3_column_int64(statement, 0),
      .client_cert_id = sqlite3_column_int64(statement, 1),
      .service_name = service_name != nullptr ? service_name : "",
      .access_level = sqlite3_column_int(statement, 3),
      .enabled = sqlite3_column_int(statement, 4) != 0,
      .note = nullable_text(statement, 5),
      .created_at = created_at != nullptr ? created_at : "",
      .updated_at = updated_at != nullptr ? updated_at : "",
  };
}

std::optional<ClientCertRecord> query_single_client_cert(sqlite3 *db,
                                                         const char *sql,
                                                         std::int64_t id) {
  Statement statement(db, sql);
  bind_int64(statement.get(), 1, id);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result == SQLITE_DONE) {
    return std::nullopt;
  }
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to fetch client cert");
  }
  return read_client_cert(statement.get());
}

} // namespace

std::optional<ClientCertRecord>
RuleRepository::find_client_cert(std::string_view fingerprint_sha256) const {
  static constexpr auto kSql = R"SQL(
SELECT id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, enabled,
       not_before, not_after, last_used_at, last_used_ip, note, created_at,
       updated_at, revoked_at
FROM client_certs
WHERE fingerprint_sha256 = ?1
  AND enabled = 1
  AND revoked_at IS NULL
  AND (not_before IS NULL OR not_before <= CURRENT_TIMESTAMP)
  AND (not_after IS NULL OR not_after > CURRENT_TIMESTAMP)
LIMIT 1;
)SQL";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_text(statement.get(), 1, fingerprint_sha256);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result == SQLITE_DONE) {
    return std::nullopt;
  }
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to fetch client cert");
  }
  return read_client_cert(statement.get());
}

std::optional<ClientCertServiceLevelRecord>
RuleRepository::find_client_cert_service_level(
    std::int64_t client_cert_id, std::string_view service_name) const {
  static constexpr auto kSql = R"SQL(
SELECT id, client_cert_id, service_name, access_level, enabled, note, created_at, updated_at
FROM client_cert_service_levels
WHERE client_cert_id = ?1
  AND enabled = 1
  AND (service_name = ?2 OR service_name = '*')
ORDER BY CASE WHEN service_name = ?2 THEN 0 ELSE 1 END, id ASC
LIMIT 1;
)SQL";

  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1, client_cert_id);
  bind_text(statement.get(), 2, service_name);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result == SQLITE_DONE) {
    return std::nullopt;
  }
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to fetch client cert service level");
  }
  return read_client_cert_service_level(statement.get());
}

void RuleRepository::note_client_cert_success(
    std::int64_t client_cert_id, std::string_view client_ip) const {
  static constexpr auto kSql = R"SQL(
UPDATE client_certs
SET last_used_at = CURRENT_TIMESTAMP,
    last_used_ip = ?1,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?2;
)SQL";
  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_text(statement.get(), 1, client_ip);
  bind_int64(statement.get(), 2, client_cert_id);
  step_done_or_throw(statement.get(), "failed to note client cert success");
}

std::vector<ClientCertRecord> RuleRepository::list_client_certs() const {
  static constexpr auto kSql = R"SQL(
SELECT id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, enabled,
       not_before, not_after, last_used_at, last_used_ip, note, created_at,
       updated_at, revoked_at
FROM client_certs
ORDER BY fingerprint_sha256 ASC, id ASC;
)SQL";
  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  std::vector<ClientCertRecord> results;
  while (true) {
    const auto step_result = sqlite3_step(statement.get());
    if (step_result == SQLITE_DONE) {
      break;
    }
    if (step_result != SQLITE_ROW) {
      throw std::runtime_error("failed to list client certs");
    }
    results.push_back(read_client_cert(statement.get()));
  }
  return results;
}

std::vector<ClientCertServiceLevelRecord>
RuleRepository::list_client_cert_service_levels() const {
  static constexpr auto kSql = R"SQL(
SELECT id, client_cert_id, service_name, access_level, enabled, note, created_at, updated_at
FROM client_cert_service_levels
ORDER BY service_name ASC, client_cert_id ASC, id ASC;
)SQL";
  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  std::vector<ClientCertServiceLevelRecord> results;
  while (true) {
    const auto step_result = sqlite3_step(statement.get());
    if (step_result == SQLITE_DONE) {
      break;
    }
    if (step_result != SQLITE_ROW) {
      throw std::runtime_error("failed to list client cert service levels");
    }
    results.push_back(read_client_cert_service_level(statement.get()));
  }
  return results;
}

std::optional<ClientCertRecord>
RuleRepository::get_client_cert(std::int64_t client_cert_id) const {
  static constexpr auto kSql = R"SQL(
SELECT id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, enabled,
       not_before, not_after, last_used_at, last_used_ip, note, created_at,
       updated_at, revoked_at
FROM client_certs
WHERE id = ?1
LIMIT 1;
)SQL";
  SqliteConnection connection(database_path_);
  return query_single_client_cert(connection.handle(), kSql, client_cert_id);
}

std::int64_t
RuleRepository::insert_client_cert(const NewClientCert &new_client_cert) const {
  static constexpr auto kSql = R"SQL(
INSERT INTO client_certs (
    fingerprint_sha256,
    serial_number,
    subject_dn,
    issuer_dn,
    not_before,
    not_after,
    note
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
)SQL";
  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_text(statement.get(), 1, new_client_cert.fingerprint_sha256);
  bind_nullable_text(statement.get(), 2, new_client_cert.serial_number);
  bind_nullable_text(statement.get(), 3, new_client_cert.subject_dn);
  bind_nullable_text(statement.get(), 4, new_client_cert.issuer_dn);
  bind_nullable_text(statement.get(), 5, new_client_cert.not_before);
  bind_nullable_text(statement.get(), 6, new_client_cert.not_after);
  bind_nullable_text(statement.get(), 7, new_client_cert.note);
  step_done_or_throw(statement.get(), "failed to insert client cert");
  return sqlite3_last_insert_rowid(connection.handle());
}

std::int64_t RuleRepository::upsert_client_cert_service_level(
    const NewClientCertServiceLevel &new_client_cert_service_level) const {
  static constexpr auto kSql = R"SQL(
INSERT INTO client_cert_service_levels (
    client_cert_id,
    service_name,
    access_level,
    note
) VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(client_cert_id, service_name) DO UPDATE SET
    access_level = excluded.access_level,
    note = excluded.note,
    enabled = 1,
    updated_at = CURRENT_TIMESTAMP
RETURNING id;
)SQL";
  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1,
             new_client_cert_service_level.client_cert_id);
  bind_text(statement.get(), 2, new_client_cert_service_level.service_name);
  bind_int(statement.get(), 3, new_client_cert_service_level.access_level);
  bind_nullable_text(statement.get(), 4, new_client_cert_service_level.note);
  const auto step_result = sqlite3_step(statement.get());
  if (step_result != SQLITE_ROW) {
    throw std::runtime_error("failed to upsert client cert service level");
  }
  return sqlite3_column_int64(statement.get(), 0);
}

void RuleRepository::disable_client_cert(std::int64_t client_cert_id) const {
  static constexpr auto kSql = R"SQL(
UPDATE client_certs
SET enabled = 0,
    revoked_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?1;
)SQL";
  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1, client_cert_id);
  step_done_or_throw(statement.get(), "failed to disable client cert");
}

void RuleRepository::enable_client_cert(std::int64_t client_cert_id) const {
  static constexpr auto kSql = R"SQL(
UPDATE client_certs
SET enabled = 1,
    revoked_at = NULL,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?1;
)SQL";
  SqliteConnection connection(database_path_);
  Statement statement(connection.handle(), kSql);
  bind_int64(statement.get(), 1, client_cert_id);
  step_done_or_throw(statement.get(), "failed to enable client cert");
}

void RuleRepository::delete_client_cert(std::int64_t client_cert_id) const {
  static constexpr auto kDeleteLevelsSql =
      "DELETE FROM client_cert_service_levels WHERE client_cert_id = ?1;";
  static constexpr auto kDeleteCertSql =
      "DELETE FROM client_certs WHERE id = ?1;";
  SqliteConnection connection(database_path_);
  {
    Statement statement(connection.handle(), kDeleteLevelsSql);
    bind_int64(statement.get(), 1, client_cert_id);
    step_done_or_throw(statement.get(),
                       "failed to delete client cert service levels");
  }
  {
    Statement statement(connection.handle(), kDeleteCertSql);
    bind_int64(statement.get(), 1, client_cert_id);
    step_done_or_throw(statement.get(), "failed to delete client cert");
  }
}

} // namespace roche_limit::auth_store
