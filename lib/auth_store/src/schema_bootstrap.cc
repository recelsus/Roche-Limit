#include "auth_store/schema_bootstrap.h"

#include "auth_store/sqlite_connection.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace roche_limit::auth_store {

namespace {

constexpr int kLatestSchemaVersion = 1;
constexpr int kLatestMigrationVersion = 5;

std::filesystem::path source_root() {
#ifdef ROCHE_LIMIT_SOURCE_DIR
  return std::filesystem::path(ROCHE_LIMIT_SOURCE_DIR);
#else
  return std::filesystem::current_path();
#endif
}

std::filesystem::path
executable_directory(const std::filesystem::path &executable_path) {
  if (executable_path.empty()) {
    return std::filesystem::current_path();
  }
  const auto absolute_path = std::filesystem::absolute(executable_path);
  if (absolute_path.has_parent_path()) {
    return absolute_path.parent_path();
  }
  return std::filesystem::current_path();
}

std::vector<std::filesystem::path>
candidate_paths(const std::filesystem::path &executable_path) {
  const auto executable_dir = executable_directory(executable_path);
  return {
      "/var/lib/roche-limit/roche-limit.sqlite3",
      executable_dir / "roche-limit.sqlite3",
  };
}

std::vector<std::filesystem::path>
candidate_schema_paths(const std::filesystem::path &executable_path) {
  const auto executable_dir = executable_directory(executable_path);
  return {
      executable_dir / "schema" / "init.sql",
      executable_dir.parent_path() / "schema" / "init.sql",
      std::filesystem::current_path() / "schema" / "init.sql",
      source_root() / "schema" / "init.sql",
  };
}

std::vector<std::filesystem::path>
candidate_migration_dirs(const std::filesystem::path &executable_path) {
  const auto executable_dir = executable_directory(executable_path);
  return {
      executable_dir / "schema" / "migrations",
      executable_dir.parent_path() / "schema" / "migrations",
      std::filesystem::current_path() / "schema" / "migrations",
      source_root() / "schema" / "migrations",
  };
}

std::string read_file(const std::filesystem::path &path) {
  std::ifstream input(path);
  if (!input.is_open()) {
    throw std::runtime_error("failed to open file: " + path.string());
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::string load_schema_sql(const std::filesystem::path &executable_path) {
  for (const auto &path : candidate_schema_paths(executable_path)) {
    if (!std::filesystem::exists(path)) {
      continue;
    }

    auto sql = read_file(path);
    if (sql.empty()) {
      continue;
    }

    sql += R"SQL(

INSERT INTO schema_metadata (key, value, updated_at)
VALUES ('schema_version', ')SQL";
    sql += std::to_string(kLatestSchemaVersion);
    sql += R"SQL(', CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at;
)SQL";
    return sql;
  }

  throw std::runtime_error("failed to locate schema/init.sql");
}

int metadata_version(SqliteConnection &connection, std::string_view key) {
  sqlite3_stmt *statement = nullptr;
  constexpr auto kSql =
      "SELECT value FROM schema_metadata WHERE key = ?1 LIMIT 1;";
  if (sqlite3_prepare_v2(connection.handle(), kSql, -1, &statement, nullptr) !=
      SQLITE_OK) {
    throw std::runtime_error("failed to prepare schema metadata query");
  }

  const auto finalize = [&statement]() {
    if (statement != nullptr) {
      sqlite3_finalize(statement);
      statement = nullptr;
    }
  };

  if (sqlite3_bind_text(statement, 1, key.data(), static_cast<int>(key.size()),
                        SQLITE_TRANSIENT) != SQLITE_OK) {
    finalize();
    throw std::runtime_error("failed to bind schema metadata key");
  }

  const auto step_result = sqlite3_step(statement);
  if (step_result == SQLITE_DONE) {
    finalize();
    return 0;
  }
  if (step_result != SQLITE_ROW) {
    finalize();
    throw std::runtime_error("failed to read schema metadata");
  }

  const auto *text =
      reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
  const int version = text != nullptr ? std::stoi(text) : 0;
  finalize();
  return version;
}

void set_metadata_version(SqliteConnection &connection, std::string_view key,
                          int version) {
  std::string sql = R"SQL(
INSERT INTO schema_metadata (key, value, updated_at)
VALUES (')SQL";
  sql += std::string(key);
  sql += R"SQL(', ')SQL";
  sql += std::to_string(version);
  sql += R"SQL(', CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at;
)SQL";
  connection.execute(sql);
}

std::map<int, std::filesystem::path>
load_migration_files(const std::filesystem::path &executable_path) {
  std::map<int, std::filesystem::path> migrations;
  for (const auto &dir : candidate_migration_dirs(executable_path)) {
    if (!std::filesystem::is_directory(dir)) {
      continue;
    }

    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
      if (!entry.is_regular_file() || entry.path().extension() != ".sql") {
        continue;
      }

      const auto filename = entry.path().filename().string();
      const auto underscore = filename.find('_');
      const auto number_text = filename.substr(0, underscore);
      try {
        const int version = std::stoi(number_text);
        migrations.emplace(version, entry.path());
      } catch (...) {
        continue;
      }
    }
    if (!migrations.empty()) {
      return migrations;
    }
  }
  return migrations;
}

void apply_migrations(SqliteConnection &connection,
                      const std::filesystem::path &executable_path) {
  int current_version = metadata_version(connection, "migration_version");
  const auto migrations = load_migration_files(executable_path);
  for (const auto &[version, path] : migrations) {
    if (version <= current_version) {
      continue;
    }

    connection.execute("BEGIN IMMEDIATE;");
    try {
      const auto sql = read_file(path);
      if (!sql.empty()) {
        connection.execute(sql);
      }
      set_metadata_version(connection, "migration_version", version);
      connection.execute("COMMIT;");
      current_version = version;
    } catch (...) {
      connection.execute("ROLLBACK;");
      throw;
    }
  }
}

BootstrapResult
bootstrap_at_path(const std::filesystem::path &database_path,
                  const std::filesystem::path &executable_path) {
  const bool file_existed = std::filesystem::exists(database_path);
  std::filesystem::create_directories(database_path.parent_path());

  SqliteConnection connection(database_path);
  if (!file_existed || !connection.table_exists("schema_metadata")) {
    connection.execute(load_schema_sql(executable_path));
    set_metadata_version(connection, "migration_version",
                         kLatestMigrationVersion);
  } else {
    const bool has_plain_api_key_column =
        connection.column_exists("api_keys", "key_plain");
    if (has_plain_api_key_column) {
      set_metadata_version(connection, "migration_version", 0);
    }
    apply_migrations(connection, executable_path);
    connection.execute(load_schema_sql(executable_path));
  }

  if (!connection.table_exists("schema_metadata")) {
    throw std::runtime_error("sqlite database is missing schema_metadata");
  }

  constexpr std::array expected_tables{
      "schema_metadata",
      "ip_rules",
      "ip_service_levels",
      "api_keys",
      "users",
      "user_credentials",
      "user_service_levels",
      "user_sessions",
      "login_failures",
      "csrf_tokens",
      "audit_events",
  };

  for (const auto *table_name : expected_tables) {
    if (!connection.table_exists(table_name)) {
      throw std::runtime_error(
          std::string("required sqlite table is missing after bootstrap: ") +
          table_name);
    }
  }

  return BootstrapResult{
      .database_path = database_path,
      .database_file_created = !file_existed,
      .schema_created = true,
  };
}

} // namespace

BootstrapResult
bootstrap_sqlite_schema(const std::filesystem::path &executable_path) {
  std::runtime_error last_error("sqlite bootstrap failed");

  for (const auto &path : candidate_paths(executable_path)) {
    try {
      if (std::filesystem::exists(path)) {
        return bootstrap_at_path(path, executable_path);
      }
    } catch (const std::exception &ex) {
      last_error = std::runtime_error(ex.what());
    }
  }

  for (const auto &path : candidate_paths(executable_path)) {
    try {
      return bootstrap_at_path(path, executable_path);
    } catch (const std::exception &ex) {
      last_error = std::runtime_error(ex.what());
    }
  }

  throw last_error;
}

BootstrapResult
bootstrap_sqlite_schema_at(const std::filesystem::path &database_path,
                           const std::filesystem::path &executable_path) {
  return bootstrap_at_path(database_path, executable_path);
}

} // namespace roche_limit::auth_store
