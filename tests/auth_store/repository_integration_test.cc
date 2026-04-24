#include "auth_core/api_key_hasher.h"
#include "auth_core/auth_service.h"
#include "auth_store/audit_repository.h"
#include "auth_store/rule_repository.h"
#include "auth_store/schema_bootstrap.h"
#include "auth_store/sqlite_connection.h"
#include "auth_store/user_repository.h"
#include "common/hash_util.h"

#include <sqlite3.h>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::AuthDecision;
using roche_limit::auth_core::AuthService;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleType;
using roche_limit::auth_core::RequestContext;
using roche_limit::auth_store::AuditRepository;
using roche_limit::auth_store::NewApiKeyRecord;
using roche_limit::auth_store::NewAuditEvent;
using roche_limit::auth_store::NewIpRule;
using roche_limit::auth_store::NewIpServiceLevel;
using roche_limit::auth_store::NewUserRecord;
using roche_limit::auth_store::NewUserServiceLevel;
using roche_limit::auth_store::RuleRepository;
using roche_limit::auth_store::SqliteConnection;
using roche_limit::auth_store::UserRepository;

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "test failure: " << message << std::endl;
  std::exit(1);
}

void expect(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

std::filesystem::path test_database_path(std::string_view name) {
  auto dir =
      std::filesystem::temp_directory_path() / "roche-limit-auth-store-tests";
  std::filesystem::create_directories(dir);
  return dir / (std::string(name) + ".sqlite3");
}

void reset_database(const std::filesystem::path &path) {
  std::error_code error;
  std::filesystem::remove(path, error);
}

std::string scalar_text(const std::filesystem::path &database_path,
                        const char *sql) {
  SqliteConnection connection(database_path);
  sqlite3_stmt *statement = nullptr;
  if (sqlite3_prepare_v2(connection.handle(), sql, -1, &statement, nullptr) !=
      SQLITE_OK) {
    fail("failed to prepare scalar query");
  }

  const auto step_result = sqlite3_step(statement);
  if (step_result != SQLITE_ROW) {
    sqlite3_finalize(statement);
    fail("scalar query returned no row");
  }

  const auto *text =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
  std::string result = text != nullptr ? text : "";
  sqlite3_finalize(statement);
  return result;
}

int scalar_int(const std::filesystem::path &database_path, const char *sql) {
  SqliteConnection connection(database_path);
  sqlite3_stmt *statement = nullptr;
  if (sqlite3_prepare_v2(connection.handle(), sql, -1, &statement, nullptr) !=
      SQLITE_OK) {
    fail("failed to prepare integer scalar query");
  }

  const auto step_result = sqlite3_step(statement);
  if (step_result != SQLITE_ROW) {
    sqlite3_finalize(statement);
    fail("integer scalar query returned no row");
  }

  const int result = sqlite3_column_int(statement, 0);
  sqlite3_finalize(statement);
  return result;
}

void test_bootstrap_creates_current_schema() {
  const auto database_path = test_database_path("bootstrap-current");
  reset_database(database_path);

  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  SqliteConnection connection(database_path);
  expect(connection.table_exists("api_keys"), "api_keys table should exist");
  expect(!connection.column_exists("api_keys", "key_plain"),
         "new schema should not include key_plain");
  expect(connection.column_exists("api_keys", "key_lookup_hash"),
         "new schema should include key_lookup_hash");
  expect(connection.column_exists("api_keys", "last_used_at"),
         "new schema should include api key usage columns");
  expect(connection.column_exists("api_keys", "failed_attempts"),
         "new schema should include api key failure counters");
  expect(connection.table_exists("audit_events"),
         "audit_events table should exist");
  expect(connection.table_exists("login_failures"),
         "login_failures table should exist");
  expect(connection.table_exists("csrf_tokens"),
         "csrf_tokens table should exist");
  expect(scalar_text(database_path, "SELECT value FROM schema_metadata WHERE "
                                    "key = 'migration_version';") == "7",
         "new schema should mark latest migration version");
}

void test_legacy_key_plain_column_is_migrated() {
  const auto database_path = test_database_path("legacy-key-plain");
  reset_database(database_path);
  {
    SqliteConnection connection(database_path);
    connection.execute(R"SQL(
CREATE TABLE schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO schema_metadata (key, value) VALUES ('migration_version', '0');
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY,
    key_plain TEXT,
    key_hash TEXT NOT NULL,
    key_prefix TEXT,
    service_name TEXT,
    access_level INTEGER NOT NULL CHECK (access_level >= 0),
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (key_hash, service_name)
);
)SQL");
  }

  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  SqliteConnection connection(database_path);
  expect(!connection.column_exists("api_keys", "key_plain"),
         "migration should remove legacy key_plain column");
  expect(connection.column_exists("api_keys", "key_lookup_hash"),
         "migration should add key_lookup_hash column");
  expect(connection.column_exists("api_keys", "last_used_at"),
         "migration should add api key usage columns");
  expect(connection.column_exists("api_keys", "failed_attempts"),
         "migration should add api key failure counters");
  expect(connection.table_exists("audit_events"),
         "migration should add audit_events table");
  expect(connection.table_exists("login_failures"),
         "migration should add login_failures table");
  expect(connection.table_exists("csrf_tokens"),
         "migration should add csrf_tokens table");
  expect(scalar_text(database_path, "SELECT value FROM schema_metadata WHERE "
                                    "key = 'migration_version';") == "7",
         "migration should store latest migration version");
}

void test_api_key_repository_stores_hash_and_prefix_only() {
  const auto database_path = test_database_path("api-key-repository");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  RuleRepository repository(database_path);
  const std::string plain_key = "test-api-key-value";
  const auto key_hash = roche_limit::auth_core::hash_api_key(plain_key);
  const auto key_lookup_hash =
      roche_limit::auth_core::api_key_lookup_hash(plain_key);
  const auto id = repository.insert_api_key(NewApiKeyRecord{
      .key_hash = key_hash,
      .key_lookup_hash = key_lookup_hash,
      .key_prefix = "test-api",
      .service_name = std::string("primary"),
      .access_level = 60,
      .expires_at = std::nullopt,
      .note = std::string("integration"),
  });

  const auto records = repository.list_api_keys();
  expect(records.size() == 1, "one api key should be listed");
  expect(records.front().id == id,
         "listed api key id should match inserted id");
  expect(records.front().key_hash == key_hash,
         "api key hash should be persisted");
  expect(records.front().key_lookup_hash == key_lookup_hash,
         "api key lookup hash should be persisted");
  expect(records.front().key_prefix.has_value() &&
             *records.front().key_prefix == "test-api",
         "api key prefix should be persisted");
  expect(records.front().failed_attempts == 0,
         "new api key should start with zero failures");

  const auto found = repository.find_api_key(key_lookup_hash, "primary");
  expect(found.has_value(),
         "api key should be found by lookup hash and service");
  expect(found->access_level == 60, "api key access level should be preserved");

  repository.note_api_key_success(id, "198.51.100.20");
  repository.note_api_key_failure(id, "198.51.100.21");

  const auto refreshed = repository.get_api_key(id);
  expect(refreshed.has_value(), "api key should still be readable by id");
  expect(refreshed->last_used_at.has_value(),
         "successful use should update last_used_at");
  expect(refreshed->last_used_ip.has_value() &&
             *refreshed->last_used_ip == "198.51.100.21",
         "last_used_ip should reflect the latest observation");
  expect(refreshed->last_failed_at.has_value(),
         "failed use should update last_failed_at");
  expect(refreshed->failed_attempts == 1,
         "failed use should increment failed_attempts");
}

void test_expired_api_key_is_auto_disabled() {
  const auto database_path = test_database_path("api-key-expiry");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  RuleRepository repository(database_path);
  const std::string plain_key = "expired-api-key";
  const auto id = repository.insert_api_key(NewApiKeyRecord{
      .key_hash = roche_limit::auth_core::hash_api_key(plain_key),
      .key_lookup_hash = roche_limit::auth_core::api_key_lookup_hash(plain_key),
      .key_prefix = roche_limit::auth_core::api_key_prefix(plain_key),
      .service_name = std::string("primary"),
      .access_level = 60,
      .expires_at = std::string("2000-01-01 00:00:00"),
      .note = std::nullopt,
  });

  expect(!repository.find_api_key(
              roche_limit::auth_core::api_key_lookup_hash(plain_key), "primary")
              .has_value(),
         "expired api key should not be returned");
  const auto expired = repository.get_api_key(id);
  expect(expired.has_value() && !expired->enabled,
         "expired api key should be auto-disabled");
}

void test_ip_remove_deletes_service_levels() {
  const auto database_path = test_database_path("ip-remove-cascade");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  RuleRepository repository(database_path);
  const auto ip_rule_id = repository.insert_ip_rule(NewIpRule{
      .value_text = "198.51.100.10",
      .address_family = AddressFamily::IPv4,
      .rule_type = IpRuleType::Single,
      .prefix_length = 32,
      .effect = IpRuleEffect::Allow,
      .note = std::nullopt,
  });
  repository.upsert_ip_service_level(NewIpServiceLevel{
      .ip_rule_id = ip_rule_id,
      .service_name = "*",
      .access_level = 90,
      .note = std::nullopt,
  });

  repository.delete_ip_rule(ip_rule_id);

  expect(scalar_int(database_path, "SELECT COUNT(*) FROM ip_rules;") == 0,
         "ip rule should be deleted");
  expect(scalar_int(database_path, "SELECT COUNT(*) FROM ip_service_levels;") ==
             0,
         "dependent ip service levels should be deleted");
}

void test_user_session_lookup_returns_non_revoked_rows() {
  const auto database_path = test_database_path("session-expiry");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  UserRepository repository(database_path);
  const auto user_id = repository.insert_user(NewUserRecord{
      .username = "alice",
      .note = std::nullopt,
  });
  repository.upsert_user_service_level(NewUserServiceLevel{
      .user_id = user_id,
      .service_name = "*",
      .access_level = 60,
      .note = std::nullopt,
  });

  const auto active_hash = roche_limit::common::sha256_hex("active-session");
  const auto expired_hash = roche_limit::common::sha256_hex("expired-session");
  repository.insert_user_session(user_id, active_hash, "2099-01-01 00:00:00",
                                 "2099-01-01 00:00:00",
                                 "2099-01-01 00:00:00");
  repository.insert_user_session(user_id, expired_hash, "2000-01-01 00:00:00",
                                 "2000-01-01 00:00:00",
                                 "2000-01-01 00:00:00");

  expect(repository.find_active_user_session(active_hash).has_value(),
         "future session should be returned");
  expect(repository.find_active_user_session(expired_hash).has_value(),
         "expiry checks are handled by the service layer");
}

void test_audit_cleanup_records_event_and_enforces_row_cap() {
  const auto database_path = test_database_path("audit-cleanup");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  AuditRepository repository(database_path);
  repository.insert_event(NewAuditEvent{
      .event_type = "auth_deny",
      .actor_type = "ip",
      .result = "deny",
      .reason = "test",
  });
  repository.cleanup(90, 1);

  expect(scalar_int(database_path, "SELECT COUNT(*) FROM audit_events;") == 1,
         "audit cleanup should enforce max rows");
  expect(scalar_text(database_path,
                     "SELECT event_type FROM audit_events LIMIT 1;") ==
             "audit_cleanup",
         "audit cleanup should record a cleanup event");
  expect(scalar_int(database_path,
                    "SELECT COUNT(*) FROM audit_events WHERE event_hash IS NOT NULL;") == 1,
         "audit events should always carry a chain hash");
}

void test_audit_event_metadata_and_hash_chain_are_standardized() {
  const auto database_path = test_database_path("audit-hash-chain");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  AuditRepository repository(database_path);
  repository.insert_event(NewAuditEvent{
      .event_type = "auth_deny",
      .actor_type = "ip",
      .client_ip = std::string("198.51.100.1"),
      .request_id = std::string("rl-1"),
      .result = "deny",
      .reason = "test",
      .metadata_json = std::string("{\"detail\":\"first\"}"),
  });
  repository.insert_event(NewAuditEvent{
      .event_type = "login_success",
      .actor_type = "user",
      .actor_id = std::string("1"),
      .result = "success",
      .metadata_json = std::string("{\"detail\":\"second\"}"),
  });

  expect(scalar_int(database_path, "SELECT COUNT(*) FROM audit_events WHERE event_hash IS NOT NULL;") == 2,
         "audit hash chain should populate event_hash");
  expect(scalar_int(database_path, "SELECT COUNT(*) FROM audit_events WHERE prev_event_hash IS NOT NULL;") == 1,
         "second audit event should point to previous hash");
  const auto metadata = scalar_text(
      database_path,
      "SELECT metadata_json FROM audit_events WHERE event_type = 'auth_deny' LIMIT 1;");
  expect(metadata.find("\"schema_version\":1") != std::string::npos,
         "audit metadata should include schema version");
  expect(metadata.find("\"details\":{\"detail\":\"first\"}") != std::string::npos,
         "audit metadata should wrap details under a standard key");
}

void test_concurrent_auth_requests_share_repository_safely() {
  const auto database_path = test_database_path("concurrent-auth");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  auto repository = std::make_shared<RuleRepository>(database_path);
  repository->insert_api_key(NewApiKeyRecord{
      .key_hash = roche_limit::auth_core::hash_api_key("thread-safe-key"),
      .key_lookup_hash =
          roche_limit::auth_core::api_key_lookup_hash("thread-safe-key"),
      .key_prefix = roche_limit::auth_core::api_key_prefix("thread-safe-key"),
      .service_name = std::string("primary"),
      .access_level = 90,
      .expires_at = std::nullopt,
      .note = std::nullopt,
  });
  AuthService service(repository);

  constexpr int kThreadCount = 8;
  constexpr int kRequestsPerThread = 20;
  std::vector<std::thread> threads;
  std::vector<int> allow_counts(kThreadCount, 0);
  std::vector<std::string> errors;
  std::mutex errors_mutex;

  for (int thread_index = 0; thread_index < kThreadCount; ++thread_index) {
    threads.emplace_back([&, thread_index]() {
      try {
        for (int request_index = 0; request_index < kRequestsPerThread;
             ++request_index) {
          const auto result = service.authorize(RequestContext{
              .client_ip = "198.51.100.20",
              .service_name = "primary",
              .api_key = std::string("thread-safe-key"),
          });
          if (result.decision == AuthDecision::Allow &&
              result.access_level == 90) {
            ++allow_counts[thread_index];
          }
        }
      } catch (const std::exception &ex) {
        std::lock_guard<std::mutex> lock(errors_mutex);
        errors.push_back(ex.what());
      }
    });
  }
  for (auto &thread : threads) {
    thread.join();
  }

  expect(errors.empty(), "concurrent auth requests should not throw");
  for (const auto count : allow_counts) {
    expect(count == kRequestsPerThread,
           "each concurrent auth request should allow consistently");
  }
}

void test_write_fails_cleanly_while_database_is_locked() {
  const auto database_path = test_database_path("database-locked");
  reset_database(database_path);
  roche_limit::auth_store::bootstrap_sqlite_schema_at(database_path, {});

  SqliteConnection lock_connection(database_path);
  lock_connection.execute("BEGIN EXCLUSIVE;");

  RuleRepository repository(database_path);
  bool threw = false;
  std::string error_text;
  try {
    repository.insert_ip_rule(NewIpRule{
        .value_text = "203.0.113.40",
        .address_family = AddressFamily::IPv4,
        .rule_type = IpRuleType::Single,
        .prefix_length = 32,
        .effect = IpRuleEffect::Allow,
        .note = std::nullopt,
    });
  } catch (const std::exception &ex) {
    threw = true;
    error_text = ex.what();
  }
  lock_connection.execute("ROLLBACK;");

  expect(threw, "locked database should surface an exception");
  expect(error_text.find("locked") != std::string::npos,
         "locked database error should mention lock state");
}

} // namespace

int main() {
  setenv("ROCHE_LIMIT_API_KEY_PEPPER", "test-pepper", 1);

  test_bootstrap_creates_current_schema();
  test_legacy_key_plain_column_is_migrated();
  test_api_key_repository_stores_hash_and_prefix_only();
  test_expired_api_key_is_auto_disabled();
  test_ip_remove_deletes_service_levels();
  test_user_session_lookup_returns_non_revoked_rows();
  test_audit_cleanup_records_event_and_enforces_row_cap();
  test_audit_event_metadata_and_hash_chain_are_standardized();
  test_concurrent_auth_requests_share_repository_safely();
  test_write_fails_cleanly_while_database_is_locked();
  std::cout << "roche_limit_auth_store_integration_tests: ok" << std::endl;
  return 0;
}
