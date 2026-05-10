#include "app_config.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {

void expect(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << "test failure: " << message << std::endl;
    std::exit(1);
  }
}

void clear_env() {
  unsetenv("ROCHE_LIMIT_API_KEY_PEPPER");
  unsetenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  unsetenv("ROCHE_LIMIT_ALLOWED_PEERS");
  unsetenv("ROCHE_LIMIT_TRUSTED_PROXIES");
  unsetenv("ROCHE_LIMIT_UNKNOWN_IP_LEVEL");
  unsetenv("ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL");
  unsetenv("ROCHE_LIMIT_METRICS_MODE");
  unsetenv("ROCHE_LIMIT_METRICS_ALLOW_PUBLIC");
  unsetenv("ROCHE_LIMIT_SESSION_COOKIE_SECURE");
  unsetenv("ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY");
  unsetenv("ROCHE_LIMIT_AUDIT_RETENTION_DAYS");
  unsetenv("ROCHE_LIMIT_AUDIT_MAX_ROWS");
}

bool load_throws() {
  try {
    static_cast<void>(roche_limit::server::config::load_app_config(
        std::filesystem::path{"test.sqlite3"}));
  } catch (const std::runtime_error &) {
    return true;
  }
  return false;
}

void test_default_mode_is_internal() {
  clear_env();
  setenv("ROCHE_LIMIT_API_KEY_PEPPER", "test-pepper", 1);

  const auto config = roche_limit::server::config::load_app_config(
      std::filesystem::path{"test.sqlite3"});
  expect(config.deployment_mode ==
             roche_limit::server::config::DeploymentMode::Internal,
         "default deployment mode should be internal");
}

void test_public_mode_requires_peer_restriction() {
  clear_env();
  setenv("ROCHE_LIMIT_API_KEY_PEPPER",
         "0123456789abcdef0123456789abcdef", 1);
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "public", 1);
  setenv("ROCHE_LIMIT_METRICS_MODE", "internal", 1);

  expect(load_throws(),
         "public mode should fail fast without peer restrictions");

  setenv("ROCHE_LIMIT_ALLOWED_PEERS", "127.0.0.1", 1);
  const auto config = roche_limit::server::config::load_app_config(
      std::filesystem::path{"test.sqlite3"});
  expect(config.deployment_mode ==
             roche_limit::server::config::DeploymentMode::Public,
         "public mode should load when allowed peers are configured");
}

void test_public_mode_rejects_weak_secret() {
  clear_env();
  setenv("ROCHE_LIMIT_API_KEY_PEPPER", "test-pepper", 1);
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "public", 1);
  setenv("ROCHE_LIMIT_ALLOWED_PEERS", "127.0.0.1", 1);
  setenv("ROCHE_LIMIT_METRICS_MODE", "internal", 1);

  expect(load_throws(), "public mode should reject weak API key pepper");
}

void test_public_mode_rejects_high_unknown_default() {
  clear_env();
  setenv("ROCHE_LIMIT_API_KEY_PEPPER",
         "0123456789abcdef0123456789abcdef", 1);
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "public", 1);
  setenv("ROCHE_LIMIT_ALLOWED_PEERS", "127.0.0.1", 1);
  setenv("ROCHE_LIMIT_METRICS_MODE", "internal", 1);
  setenv("ROCHE_LIMIT_UNKNOWN_IP_LEVEL", "30", 1);

  expect(load_throws(),
         "public mode should reject high unknown IP default level");
}

void test_hardened_mode_requires_fail_closed_defaults() {
  clear_env();
  setenv("ROCHE_LIMIT_API_KEY_PEPPER",
         "0123456789abcdef0123456789abcdef", 1);
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "hardened", 1);
  setenv("ROCHE_LIMIT_ALLOWED_PEERS", "127.0.0.1", 1);
  setenv("ROCHE_LIMIT_TRUSTED_PROXIES", "127.0.0.1", 1);
  setenv("ROCHE_LIMIT_METRICS_MODE", "internal", 1);
  setenv("ROCHE_LIMIT_UNKNOWN_IP_LEVEL", "1", 1);

  expect(load_throws(),
         "hardened mode should reject unknown IP level above zero");

  setenv("ROCHE_LIMIT_UNKNOWN_IP_LEVEL", "0", 1);
  setenv("ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL", "1", 1);
  expect(load_throws(),
         "hardened mode should reject shared allow level above zero");
}

void test_hardened_mode_requires_metrics_protection() {
  clear_env();
  setenv("ROCHE_LIMIT_API_KEY_PEPPER",
         "0123456789abcdef0123456789abcdef", 1);
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "hardened", 1);
  setenv("ROCHE_LIMIT_ALLOWED_PEERS", "127.0.0.1", 1);
  setenv("ROCHE_LIMIT_TRUSTED_PROXIES", "127.0.0.1", 1);

  expect(load_throws(),
         "hardened mode should reject default unprotected metrics");
}

void test_invalid_deployment_mode_fails_fast() {
  clear_env();
  setenv("ROCHE_LIMIT_API_KEY_PEPPER", "test-pepper", 1);
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "internet", 1);

  expect(load_throws(), "invalid deployment mode should fail fast");
}

} // namespace

int main() {
  test_default_mode_is_internal();
  test_public_mode_requires_peer_restriction();
  test_public_mode_rejects_weak_secret();
  test_public_mode_rejects_high_unknown_default();
  test_hardened_mode_requires_fail_closed_defaults();
  test_hardened_mode_requires_metrics_protection();
  test_invalid_deployment_mode_fails_fast();
  clear_env();

  std::cout << "roche_limit_app_config_tests: ok" << std::endl;
  return 0;
}
