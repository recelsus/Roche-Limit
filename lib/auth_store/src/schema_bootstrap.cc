#include "auth_store/schema_bootstrap.h"

#include "auth_store/sqlite_connection.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace roche_limit::auth_store {

namespace {

constexpr auto kSchemaVersion = "1";

std::filesystem::path source_root() {
#ifdef ROCHE_LIMIT_SOURCE_DIR
    return std::filesystem::path(ROCHE_LIMIT_SOURCE_DIR);
#else
    return std::filesystem::current_path();
#endif
}

std::filesystem::path executable_directory(const std::filesystem::path& executable_path) {
    if (executable_path.empty()) {
        return std::filesystem::current_path();
    }
    const auto absolute_path = std::filesystem::absolute(executable_path);
    if (absolute_path.has_parent_path()) {
        return absolute_path.parent_path();
    }
    return std::filesystem::current_path();
}

std::vector<std::filesystem::path> candidate_paths(const std::filesystem::path& executable_path) {
    const auto executable_dir = executable_directory(executable_path);
    return {
        "/var/lib/roche-limit/roche-limit.sqlite3",
        executable_dir / "roche-limit.sqlite3",
    };
}

std::vector<std::filesystem::path> candidate_schema_paths(
    const std::filesystem::path& executable_path) {
    const auto executable_dir = executable_directory(executable_path);
    return {
        executable_dir / "schema" / "init.sql",
        executable_dir.parent_path() / "schema" / "init.sql",
        std::filesystem::current_path() / "schema" / "init.sql",
        source_root() / "schema" / "init.sql",
    };
}

std::string load_schema_sql(const std::filesystem::path& executable_path) {
    for (const auto& path : candidate_schema_paths(executable_path)) {
        if (!std::filesystem::exists(path)) {
            continue;
        }

        std::ifstream input(path);
        if (!input.is_open()) {
            continue;
        }

        std::ostringstream buffer;
        buffer << input.rdbuf();
        auto sql = buffer.str();
        if (sql.empty()) {
            continue;
        }

        sql += R"SQL(

INSERT INTO schema_metadata (key, value, updated_at)
VALUES ('schema_version', ')SQL";
        sql += kSchemaVersion;
        sql += R"SQL(', CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at;
)SQL";
        return sql;
    }

    throw std::runtime_error("failed to locate schema/init.sql");
}

BootstrapResult bootstrap_at_path(const std::filesystem::path& database_path,
                                  const std::filesystem::path& executable_path) {
    const bool file_existed = std::filesystem::exists(database_path);
    std::filesystem::create_directories(database_path.parent_path());

    SqliteConnection connection(database_path);
    connection.execute(load_schema_sql(executable_path));

    if (!connection.column_exists("api_keys", "key_plain")) {
        connection.execute("ALTER TABLE api_keys ADD COLUMN key_plain TEXT;");
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
    };

    for (const auto* table_name : expected_tables) {
        if (!connection.table_exists(table_name)) {
            throw std::runtime_error(std::string("required sqlite table is missing after bootstrap: ") +
                                     table_name);
        }
    }

    return BootstrapResult{
        .database_path = database_path,
        .database_file_created = !file_existed,
        .schema_created = true,
    };
}

}  // namespace

BootstrapResult bootstrap_sqlite_schema(const std::filesystem::path& executable_path) {
    std::runtime_error last_error("sqlite bootstrap failed");

    for (const auto& path : candidate_paths(executable_path)) {
        try {
            if (std::filesystem::exists(path)) {
                return bootstrap_at_path(path, executable_path);
            }
        } catch (const std::exception& ex) {
            last_error = std::runtime_error(ex.what());
        }
    }

    for (const auto& path : candidate_paths(executable_path)) {
        try {
            return bootstrap_at_path(path, executable_path);
        } catch (const std::exception& ex) {
            last_error = std::runtime_error(ex.what());
        }
    }

    throw last_error;
}

}  // namespace roche_limit::auth_store
