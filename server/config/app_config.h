#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace roche_limit::server::config {

enum class DeploymentMode {
  Internal,
  Public,
  Hardened,
};

struct AppConfig {
  std::string listen_address;
  std::uint16_t port;
  std::filesystem::path database_path;
  DeploymentMode deployment_mode;
  int audit_retention_days;
  int audit_max_rows;
};

AppConfig load_app_config(const std::filesystem::path &database_path);
std::string_view deployment_mode_name(DeploymentMode mode) noexcept;

} // namespace roche_limit::server::config
