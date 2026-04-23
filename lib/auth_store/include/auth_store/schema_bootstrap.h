#pragma once

#include <filesystem>
#include <string>

namespace roche_limit::auth_store {

struct BootstrapResult {
    std::filesystem::path database_path;
    bool database_file_created{false};
    bool schema_created{false};
};

BootstrapResult bootstrap_sqlite_schema(const std::filesystem::path& executable_path);
BootstrapResult bootstrap_sqlite_schema_at(const std::filesystem::path& database_path,
                                           const std::filesystem::path& executable_path);

}  // namespace roche_limit::auth_store
