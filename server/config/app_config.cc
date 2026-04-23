#include "app_config.h"

#include <charconv>
#include <cstdlib>
#include <stdexcept>
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

} // namespace

AppConfig load_app_config(const std::filesystem::path &database_path) {
  require_non_empty_env("ROCHE_LIMIT_API_KEY_PEPPER");

  return AppConfig{
      .listen_address = "0.0.0.0",
      .port = 8080,
      .database_path = database_path,
      .audit_retention_days =
          env_int_or_default("ROCHE_LIMIT_AUDIT_RETENTION_DAYS", 90),
      .audit_max_rows = env_int_or_default("ROCHE_LIMIT_AUDIT_MAX_ROWS", 10000),
  };
}

} // namespace roche_limit::server::config
