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

void test_help_text_is_organized_by_domain_and_action() {
  const auto top = roche_limit::cli::help_text();
  expect(top.find("Commands:") != std::string::npos,
         "top help should group command domains");
  expect(top.find("roche_limit_cli key rotate") == std::string::npos,
         "top help should not enumerate every action");

  const auto key = roche_limit::cli::help_text("key");
  expect(key.find("High-impact actions:") != std::string::npos,
         "key help should group high-impact actions");
  expect(key.find("disable-all") != std::string::npos,
         "key help should include emergency disable");

  const auto rotate = roche_limit::cli::help_text("key", "rotate");
  expect(rotate.find("roche_limit_cli key rotate") != std::string::npos,
         "action help should include exact usage");
  expect(rotate.find("--force") != std::string::npos,
         "destructive action help should explain force requirement");

  const auto audit = roche_limit::cli::help_text("audit");
  expect(audit.find("Read actions:") != std::string::npos,
         "audit help should separate read actions");
  expect(audit.find("list") != std::string::npos &&
             audit.find("show") != std::string::npos,
         "audit help should include list and show");

  const auto audit_list = roche_limit::cli::help_text("audit", "list");
  expect(audit_list.find("--request-id") != std::string::npos,
         "audit list help should describe filters");
}

void test_command_domains_and_actions_are_recognized_before_dispatch() {
  expect(roche_limit::cli::is_known_command_domain("ip"),
         "ip should be a known command domain");
  expect(roche_limit::cli::is_known_command_domain("audit"),
         "audit should be a known command domain");
  expect(!roche_limit::cli::is_known_command_domain("unknown"),
         "unknown command domain should be rejected");

  expect(roche_limit::cli::is_known_command_action("ip", "set"),
         "ip set should be a known action");
  expect(roche_limit::cli::is_known_command_action("key", "rotate"),
         "key rotate should be a known action");
  expect(roche_limit::cli::is_known_command_action("user", "session-list"),
         "user session-list should be a known action");
  expect(roche_limit::cli::is_known_command_action("audit", "show"),
         "audit show should be a known action");
  expect(!roche_limit::cli::is_known_command_action("ip", "unknown"),
         "unknown action should be rejected");

  expect(roche_limit::cli::command_action_requires_target("ip", "add"),
         "ip add should require a target");
  expect(roche_limit::cli::command_action_requires_target("audit", "show"),
         "audit show should require a target");
  expect(!roche_limit::cli::command_action_requires_target("ip", "list"),
         "ip list should not require a target");
  expect(!roche_limit::cli::command_action_requires_target("key", "gen"),
         "key gen should not require a target");
}

} // namespace

int main() {
  test_plain_api_key_is_redacted();
  test_password_is_redacted();
  test_force_flag_is_required_for_destructive_commands();
  test_dry_run_flag_is_detected();
  test_help_text_is_organized_by_domain_and_action();
  test_command_domains_and_actions_are_recognized_before_dispatch();
  std::cout << "roche_limit_cli_audit_logging_tests: ok" << std::endl;
  return 0;
}
