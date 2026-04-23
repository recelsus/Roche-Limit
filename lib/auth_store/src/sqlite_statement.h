#pragma once

#include "auth_store/sqlite_connection.h"

#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace roche_limit::auth_store {

class Statement final {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db_, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("failed to prepare sqlite statement: ") +
                                     sqlite3_errmsg(db_));
        }
    }

    ~Statement() {
        if (statement_ != nullptr) {
            sqlite3_finalize(statement_);
            statement_ = nullptr;
        }
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    sqlite3_stmt* get() const noexcept {
        return statement_;
    }

private:
    sqlite3* db_{nullptr};
    sqlite3_stmt* statement_{nullptr};
};

inline std::optional<std::string> nullable_text(sqlite3_stmt* statement, int column) {
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        return std::nullopt;
    }

    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    return text != nullptr ? std::optional<std::string>(text) : std::nullopt;
}

inline void bind_text(sqlite3_stmt* statement, int index, std::string_view value) {
    if (sqlite3_bind_text(statement,
                          index,
                          value.data(),
                          static_cast<int>(value.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite text parameter");
    }
}

inline void bind_nullable_text(sqlite3_stmt* statement,
                               int index,
                               const std::optional<std::string>& value) {
    if (!value.has_value()) {
        if (sqlite3_bind_null(statement, index) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite null parameter");
        }
        return;
    }

    bind_text(statement, index, *value);
}

inline void bind_int64(sqlite3_stmt* statement, int index, std::int64_t value) {
    if (sqlite3_bind_int64(statement, index, value) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
}

inline void bind_int(sqlite3_stmt* statement, int index, int value) {
    if (sqlite3_bind_int(statement, index, value) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
}

inline void bind_nullable_int(sqlite3_stmt* statement, int index, const std::optional<int>& value) {
    if (!value.has_value()) {
        if (sqlite3_bind_null(statement, index) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite null integer parameter");
        }
        return;
    }

    bind_int(statement, index, *value);
}

inline void step_done_or_throw(sqlite3_stmt* statement, const std::string& message) {
    if (sqlite3_step(statement) != SQLITE_DONE) {
        throw std::runtime_error(message);
    }
}

inline void exec_sql(sqlite3* db, const char* sql, const char* message) {
    char* error_message = nullptr;
    const auto result = sqlite3_exec(db, sql, nullptr, nullptr, &error_message);
    if (result != SQLITE_OK) {
        std::string full_message = message;
        if (error_message != nullptr) {
            full_message += ": ";
            full_message += error_message;
            sqlite3_free(error_message);
        }
        throw std::runtime_error(full_message);
    }
}

inline std::vector<std::int64_t> select_ids(sqlite3* db, const char* sql, const char* message) {
    Statement statement(db, sql);
    std::vector<std::int64_t> ids;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error(message);
        }
        ids.push_back(sqlite3_column_int64(statement.get(), 0));
    }
    return ids;
}

inline void update_single_id(sqlite3* db,
                             const char* sql,
                             std::int64_t old_id,
                             std::int64_t new_id,
                             const char* message) {
    Statement statement(db, sql);
    bind_int64(statement.get(), 1, new_id);
    bind_int64(statement.get(), 2, old_id);
    step_done_or_throw(statement.get(), message);
}

template <typename T, typename Reader, typename Binder>
std::optional<T> find_one(const std::filesystem::path& database_path,
                          const char* sql,
                          Binder binder,
                          Reader reader,
                          const char* error_message) {
    SqliteConnection connection(database_path);
    Statement statement(connection.handle(), sql);
    binder(statement.get());
    const auto step_result = sqlite3_step(statement.get());
    if (step_result == SQLITE_DONE) {
        return std::nullopt;
    }
    if (step_result != SQLITE_ROW) {
        throw std::runtime_error(error_message);
    }
    return reader(statement.get());
}

}  // namespace roche_limit::auth_store
