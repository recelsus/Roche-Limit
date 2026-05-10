#include "containment_guard.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {

void expect(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << "test failure: " << message << std::endl;
    std::exit(1);
  }
}

bool contains(std::string_view haystack, std::string_view needle) {
  return haystack.find(needle) != std::string_view::npos;
}

void test_deny_burst_quarantines_ip() {
  roche_limit::server::http::reset_containment_state_for_tests();
  roche_limit::server::http::initialize_containment_config(
      roche_limit::server::http::ContainmentConfig{
          .deny_burst_window_seconds = 60,
          .deny_burst_threshold = 2,
          .quarantine_seconds = 120,
      });

  roche_limit::server::http::record_containment_signal(
      "auth", "198.51.100.10", "deny", "invalid_header");
  expect(roche_limit::server::http::containment_decision("198.51.100.10")
             .allowed,
         "first deny should not quarantine");

  roche_limit::server::http::record_containment_signal(
      "auth", "198.51.100.10", "deny", "invalid_header");
  const auto decision =
      roche_limit::server::http::containment_decision("198.51.100.10");
  expect(!decision.allowed, "second deny should quarantine");
  expect(decision.status_code == drogon::k429TooManyRequests,
         "quarantine should return 429");
  expect(decision.reason == "quarantined",
         "quarantine should expose quarantined reason");
  expect(decision.retry_after_seconds.has_value(),
         "quarantine should include retry-after");
}

void test_lockdown_threshold() {
  roche_limit::server::http::reset_containment_state_for_tests();
  roche_limit::server::http::initialize_containment_config(
      roche_limit::server::http::ContainmentConfig{
          .deny_burst_window_seconds = 60,
          .deny_burst_threshold = 0,
          .quarantine_seconds = 120,
          .lockdown_deny_burst_threshold = 2,
          .lockdown_seconds = 120,
      });

  roche_limit::server::http::record_containment_signal(
      "auth", "198.51.100.10", "deny", "invalid_header");
  roche_limit::server::http::record_containment_signal(
      "auth", "198.51.100.11", "deny", "invalid_header");
  const auto decision =
      roche_limit::server::http::containment_decision("198.51.100.12");
  expect(!decision.allowed, "global deny burst should enter lockdown");
  expect(decision.status_code == drogon::k503ServiceUnavailable,
         "lockdown should return 503");
  expect(decision.reason == "lockdown",
         "lockdown should expose lockdown reason");
}

void test_metrics_include_containment_state() {
  const auto metrics =
      roche_limit::server::http::prometheus_containment_metrics_text();
  expect(contains(metrics, "roche_limit_quarantine_active"),
         "metrics should include active quarantine gauge");
  expect(contains(metrics, "roche_limit_lockdown_active"),
         "metrics should include lockdown gauge");
}

} // namespace

int main() {
  test_deny_burst_quarantines_ip();
  test_lockdown_threshold();
  test_metrics_include_containment_state();
  roche_limit::server::http::reset_containment_state_for_tests();

  std::cout << "roche_limit_containment_guard_tests: ok" << std::endl;
  return 0;
}
