#include "audit_logging.h"

#include <cstdlib>
#include <iostream>
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

} // namespace

int main() {
  test_plain_api_key_is_redacted();
  test_password_is_redacted();
  std::cout << "roche_limit_cli_audit_logging_tests: ok" << std::endl;
  return 0;
}
