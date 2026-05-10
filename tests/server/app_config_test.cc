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
  setenv("ROCHE_LIMIT_API_KEY_PEPPER", "test-pepper", 1);
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "public", 1);

  expect(load_throws(),
         "public mode should fail fast without peer restrictions");

  setenv("ROCHE_LIMIT_ALLOWED_PEERS", "127.0.0.1", 1);
  const auto config = roche_limit::server::config::load_app_config(
      std::filesystem::path{"test.sqlite3"});
  expect(config.deployment_mode ==
             roche_limit::server::config::DeploymentMode::Public,
         "public mode should load when allowed peers are configured");
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
  test_invalid_deployment_mode_fails_fast();
  clear_env();

  std::cout << "roche_limit_app_config_tests: ok" << std::endl;
  return 0;
}
