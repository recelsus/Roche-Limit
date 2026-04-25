#include "auth_store/sqlite_connection.h"

#include <stdexcept>
#include <string>

namespace roche_limit::auth_store {

namespace {

std::runtime_error make_sqlite_error(sqlite3* db, const std::string& prefix) {
    const auto* message = db != nullptr ? sqlite3_errmsg(db) : "unknown sqlite error";
    return std::runtime_error(prefix + ": " + message);
}

}  // namespace

SqliteConnection::SqliteConnection(const std::filesystem::path& database_path) {
    if (sqlite3_open_v2(database_path.c_str(),
                        &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        nullptr) != SQLITE_OK) {
        auto error = make_sqlite_error(db_, "failed to open sqlite database");
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        throw error;
    }

    if (sqlite3_busy_timeout(db_, 5000) != SQLITE_OK) {
        auto error = make_sqlite_error(db_, "failed to configure sqlite busy timeout");
        sqlite3_close(db_);
        db_ = nullptr;
        throw error;
    }

    execute("PRAGMA journal_mode = WAL;");
    execute("PRAGMA synchronous = NORMAL;");
    execute("PRAGMA foreign_keys = ON;");
}

SqliteConnection::~SqliteConnection() {
    if (db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

SqliteConnection::SqliteConnection(SqliteConnection&& other) noexcept : db_(other.db_) {
    other.db_ = nullptr;
}

SqliteConnection& SqliteConnection::operator=(SqliteConnection&& other) noexcept {
    if (this != &other) {
        if (db_ != nullptr) {
            sqlite3_close(db_);
        }
        db_ = other.db_;
        other.db_ = nullptr;
    }
    return *this;
}

void SqliteConnection::execute(std::string_view sql) const {
    char* error_message = nullptr;
    if (sqlite3_exec(db_, sql.data(), nullptr, nullptr, &error_message) != SQLITE_OK) {
        std::string message = "failed to execute sqlite statement";
        if (error_message != nullptr) {
            message += ": ";
            message += error_message;
            sqlite3_free(error_message);
        }
        throw std::runtime_error(message);
    }
}

bool SqliteConnection::table_exists(std::string_view table_name) const {
    constexpr auto sql =
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1;";

    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &statement, nullptr) != SQLITE_OK) {
        throw make_sqlite_error(db_, "failed to prepare sqlite table existence query");
    }

    const auto finalize = [&statement]() {
        if (statement != nullptr) {
            sqlite3_finalize(statement);
            statement = nullptr;
        }
    };

    if (sqlite3_bind_text(statement,
                          1,
                          table_name.data(),
                          static_cast<int>(table_name.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) {
        finalize();
        throw make_sqlite_error(db_, "failed to bind sqlite table existence query");
    }

    const auto step_result = sqlite3_step(statement);
    const bool exists = step_result == SQLITE_ROW;
    if (step_result != SQLITE_ROW && step_result != SQLITE_DONE) {
        finalize();
        throw make_sqlite_error(db_, "failed to execute sqlite table existence query");
    }

    finalize();
    return exists;
}

bool SqliteConnection::column_exists(std::string_view table_name, std::string_view column_name) const {
    const auto sql = "PRAGMA table_info(" + std::string(table_name) + ");";

    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        throw make_sqlite_error(db_, "failed to prepare sqlite table info query");
    }

    const auto finalize = [&statement]() {
        if (statement != nullptr) {
            sqlite3_finalize(statement);
            statement = nullptr;
        }
    };

    while (true) {
        const auto step_result = sqlite3_step(statement);
        if (step_result == SQLITE_DONE) {
            finalize();
            return false;
        }
        if (step_result != SQLITE_ROW) {
            finalize();
            throw make_sqlite_error(db_, "failed to execute sqlite table info query");
        }

        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
        if (text != nullptr && column_name == text) {
            finalize();
            return true;
        }
    }
}

sqlite3* SqliteConnection::handle() const noexcept {
    return db_;
}

}  // namespace roche_limit::auth_store
