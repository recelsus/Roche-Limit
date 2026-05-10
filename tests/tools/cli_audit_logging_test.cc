#include "audit_logging.h"
#include "cli_support.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

[[noreturn]] void fail(std::string_view message) {
  std::cerr << "test failure: " << message << std::endl;
  std::exit(1);
}

void expect(bool condition, std::string_view message) {
  if (!condition) {
    fail(message);
  }
}

void test_plain_api_key_is_redacted() {
  const std::vector<std::string> args = {"roche_limit_cli", "key", "add",
                                         "super-secret-api-key", "--service",
                                         "primary"};
  const auto sanitized = roche_limit::cli::sanitize_cli_arguments(args);
  expect(sanitized.find("super-secret-api-key") == std::string::npos,
         "plain api key should be redacted");
  expect(sanitized.find("[REDACTED_API_KEY]") != std::string::npos,
         "sanitized command should show api key redaction marker");
}

void test_password_is_redacted() {
  const std::vector<std::string> args = {"roche_limit_cli", "user",
                                         "set-password", "1", "--password",
                                         "super-secret-password"};
  const auto sanitized = roche_limit::cli::sanitize_cli_arguments(args);
  expect(sanitized.find("super-secret-password") == std::string::npos,
         "password should be redacted");
  expect(sanitized.find("[REDACTED_PASSWORD]") != std::string::npos,
         "sanitized command should show password redaction marker");
}

void test_force_flag_is_required_for_destructive_commands() {
  const roche_limit::cli::OptionsMap no_force{};
  bool threw = false;
  try {
    roche_limit::cli::require_force_for_destructive_command(no_force,
                                                            "key remove");
  } catch (const std::runtime_error &ex) {
    threw = true;
    expect(std::string(ex.what()).find("--force") != std::string::npos,
           "force failure should tell operator to use --force");
  }
  expect(threw, "destructive command without --force should fail");

  const roche_limit::cli::OptionsMap with_force{{"--force", "true"}};
  roche_limit::cli::require_force_for_destructive_command(with_force,
                                                          "key remove");
}

void test_dry_run_flag_is_detected() {
  const roche_limit::cli::OptionsMap dry_run{{"--dry-run", "true"}};
  expect(roche_limit::cli::dry_run_requested(dry_run),
         "dry-run flag should be detected");

  const roche_limit::cli::OptionsMap disabled{{"--dry-run", "false"}};
  expect(!roche_limit::cli::dry_run_requested(disabled),
         "false dry-run flag should be treated as disabled");
}

} // namespace

int main() {
  test_plain_api_key_is_redacted();
  test_password_is_redacted();
  test_force_flag_is_required_for_destructive_commands();
  test_dry_run_flag_is_detected();
  std::cout << "roche_limit_cli_audit_logging_tests: ok" << std::endl;
  return 0;
}
