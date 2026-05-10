#include "app_config.h"

#include <charconv>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace roche_limit::server::config {

namespace {

int env_int_or_default(const char *name, int default_value) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return default_value;
  }

  const std::string_view text(value);
  int parsed = 0;
  const auto *begin = text.data();
  const auto *end = begin + text.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end || parsed <= 0) {
    return default_value;
  }
  return parsed;
}

void require_non_empty_env(const char *name) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    throw std::runtime_error(std::string(name) + " is required");
  }
}

bool env_is_set(const char *name) {
  const char *value = std::getenv(name);
  return value != nullptr && *value != '\0';
}

DeploymentMode load_deployment_mode_from_env() {
  const char *value = std::getenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  if (value == nullptr || *value == '\0') {
    return DeploymentMode::Internal;
  }

  const std::string_view mode(value);
  if (mode == "internal") {
    return DeploymentMode::Internal;
  }
  if (mode == "public") {
    return DeploymentMode::Public;
  }
  if (mode == "hardened") {
    return DeploymentMode::Hardened;
  }

  throw std::runtime_error(
      "ROCHE_LIMIT_DEPLOYMENT_MODE must be one of: internal, public, hardened");
}

void validate_public_like_deployment(DeploymentMode mode) {
  if (mode == DeploymentMode::Internal) {
    return;
  }

  if (!env_is_set("ROCHE_LIMIT_ALLOWED_PEERS") &&
      !env_is_set("ROCHE_LIMIT_TRUSTED_PROXIES")) {
    throw std::runtime_error(
        "ROCHE_LIMIT_DEPLOYMENT_MODE=public/hardened requires "
        "ROCHE_LIMIT_ALLOWED_PEERS or ROCHE_LIMIT_TRUSTED_PROXIES");
  }
}

} // namespace

AppConfig load_app_config(const std::filesystem::path &database_path) {
  require_non_empty_env("ROCHE_LIMIT_API_KEY_PEPPER");
  const auto deployment_mode = load_deployment_mode_from_env();
  validate_public_like_deployment(deployment_mode);

  return AppConfig{
      .listen_address = "0.0.0.0",
      .port = 8080,
      .database_path = database_path,
      .deployment_mode = deployment_mode,
      .audit_retention_days =
          env_int_or_default("ROCHE_LIMIT_AUDIT_RETENTION_DAYS", 90),
      .audit_max_rows = env_int_or_default("ROCHE_LIMIT_AUDIT_MAX_ROWS", 10000),
  };
}

std::string_view deployment_mode_name(DeploymentMode mode) noexcept {
  switch (mode) {
  case DeploymentMode::Internal:
    return "internal";
  case DeploymentMode::Public:
    return "public";
  case DeploymentMode::Hardened:
    return "hardened";
  }
  return "unknown";
}

} // namespace roche_limit::server::config
