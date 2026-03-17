#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace roche_limit::server::config {

struct AppConfig {
    std::string listen_address;
    std::uint16_t port;
    std::filesystem::path database_path;
};

AppConfig load_app_config(const std::filesystem::path& database_path);

}  // namespace roche_limit::server::config
