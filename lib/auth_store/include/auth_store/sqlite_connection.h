#pragma once

#include <sqlite3.h>

#include <filesystem>
#include <string_view>

namespace roche_limit::auth_store {

class SqliteConnection {
public:
    explicit SqliteConnection(const std::filesystem::path& database_path);
    ~SqliteConnection();

    SqliteConnection(const SqliteConnection&) = delete;
    SqliteConnection& operator=(const SqliteConnection&) = delete;

    SqliteConnection(SqliteConnection&& other) noexcept;
    SqliteConnection& operator=(SqliteConnection&& other) noexcept;

    void execute(std::string_view sql) const;
    bool table_exists(std::string_view table_name) const;
    bool column_exists(std::string_view table_name, std::string_view column_name) const;
    sqlite3* handle() const noexcept;

private:
    sqlite3* db_{nullptr};
};

}  // namespace roche_limit::auth_store
