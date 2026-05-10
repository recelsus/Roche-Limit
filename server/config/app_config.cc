#include "app_config.h"

#include <charconv>
#include <cstdlib>
#include <iostream>
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

std::string_view env_value_or_empty(const char *name) {
  const char *value = std::getenv(name);
  return value == nullptr ? std::string_view{} : std::string_view(value);
}

int env_access_level_or_default(const char *name, int fallback) {
  const auto text = env_value_or_empty(name);
  if (text.empty()) {
    return fallback;
  }

  int parsed = 0;
  const auto *begin = text.data();
  const auto *end = begin + text.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end || parsed < 0 ||
      parsed > 99) {
    throw std::runtime_error(std::string(name) +
                             " must be an integer access level in 0..99");
  }
  return parsed;
}

bool env_flag_is_disabled(const char *name) {
  const auto text = env_value_or_empty(name);
  return text == "0" || text == "false" || text == "no";
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

bool weak_or_placeholder_secret(std::string_view value) {
  if (value.size() < 32) {
    return true;
  }

  return value == "change-me" ||
         value == "change-me-long-random-secret" ||
         value == "test-pepper" ||
         value.find("placeholder") != std::string_view::npos ||
         value.find("changeme") != std::string_view::npos;
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

  const auto pepper = env_value_or_empty("ROCHE_LIMIT_API_KEY_PEPPER");
  if (weak_or_placeholder_secret(pepper)) {
    throw std::runtime_error(
        "ROCHE_LIMIT_API_KEY_PEPPER is too weak for public/hardened deployment");
  }

  const int unknown_level =
      env_access_level_or_default("ROCHE_LIMIT_UNKNOWN_IP_LEVEL", 0);
  const int shared_allow_level =
      env_access_level_or_default("ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL", 0);

  if (mode == DeploymentMode::Public) {
    if (unknown_level > 10) {
      throw std::runtime_error(
          "ROCHE_LIMIT_UNKNOWN_IP_LEVEL must be <= 10 in public deployment");
    }
    if (shared_allow_level > 10) {
      throw std::runtime_error(
          "ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL must be <= 10 in public deployment");
    }
    if (shared_allow_level > 0) {
      std::cerr << "warning: ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL > 0 in public "
                   "deployment"
                << std::endl;
    }
  }

  if (mode == DeploymentMode::Hardened &&
      (!env_is_set("ROCHE_LIMIT_ALLOWED_PEERS") ||
       !env_is_set("ROCHE_LIMIT_TRUSTED_PROXIES"))) {
    throw std::runtime_error(
        "ROCHE_LIMIT_DEPLOYMENT_MODE=hardened requires both "
        "ROCHE_LIMIT_ALLOWED_PEERS and ROCHE_LIMIT_TRUSTED_PROXIES");
  }

  if (mode == DeploymentMode::Hardened && unknown_level != 0) {
    throw std::runtime_error(
        "ROCHE_LIMIT_UNKNOWN_IP_LEVEL must be 0 in hardened deployment");
  }
  if (mode == DeploymentMode::Hardened && shared_allow_level != 0) {
    throw std::runtime_error(
        "ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL must be 0 in hardened deployment");
  }

  const auto metrics_mode = env_value_or_empty("ROCHE_LIMIT_METRICS_MODE");
  if (!metrics_mode.empty() && metrics_mode != "enabled" &&
      metrics_mode != "internal" && metrics_mode != "disabled") {
    throw std::runtime_error(
        "ROCHE_LIMIT_METRICS_MODE must be one of: enabled, internal, disabled");
  }
  if (mode == DeploymentMode::Public) {
    if (metrics_mode.empty()) {
      throw std::runtime_error(
          "ROCHE_LIMIT_METRICS_MODE must be explicitly set in public deployment");
    }
    if (metrics_mode == "enabled" &&
        env_value_or_empty("ROCHE_LIMIT_METRICS_ALLOW_PUBLIC") != "1") {
      throw std::runtime_error(
          "ROCHE_LIMIT_METRICS_MODE=enabled in public deployment requires "
          "ROCHE_LIMIT_METRICS_ALLOW_PUBLIC=1");
    }
  }
  if (mode == DeploymentMode::Hardened &&
      (metrics_mode.empty() || metrics_mode == "enabled")) {
    throw std::runtime_error(
        "ROCHE_LIMIT_METRICS_MODE must be internal or disabled in hardened deployment");
  }

  if (env_flag_is_disabled("ROCHE_LIMIT_SESSION_COOKIE_SECURE")) {
    throw std::runtime_error(
        "ROCHE_LIMIT_SESSION_COOKIE_SECURE must stay enabled in public/hardened deployment");
  }
  if (mode == DeploymentMode::Hardened &&
      env_flag_is_disabled("ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY")) {
    throw std::runtime_error(
        "ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY must stay enabled in hardened deployment");
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
