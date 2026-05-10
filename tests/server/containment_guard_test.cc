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

void clear_denylist_env() {
  unsetenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_IPS");
  unsetenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_API_KEY_IDS");
  unsetenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_SESSION_IDS");
  unsetenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_USER_IDS");
}

void test_deny_burst_quarantines_ip() {
  clear_denylist_env();
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
  clear_denylist_env();
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

void test_subject_quarantine_and_signal_metrics() {
  clear_denylist_env();
  roche_limit::server::http::reset_containment_state_for_tests();
  roche_limit::server::http::initialize_containment_config(
      roche_limit::server::http::ContainmentConfig{
          .deny_burst_window_seconds = 60,
          .deny_burst_threshold = 2,
          .quarantine_seconds = 120,
      });
  const auto subject = roche_limit::server::http::ContainmentSubject{
      .type = "api_key",
      .id = "42",
  };

  roche_limit::server::http::record_containment_signal_for_subject(
      subject, "auth", "deny", "insufficient_level");
  roche_limit::server::http::record_containment_signal_for_subject(
      subject, "auth", "deny", "insufficient_level");

  const auto decision =
      roche_limit::server::http::containment_decision_for_subject(subject);
  expect(!decision.allowed, "api key subject should be quarantined");
  const auto metrics =
      roche_limit::server::http::prometheus_containment_metrics_text();
  expect(contains(metrics,
                  "subject_type=\"api_key\",signal_kind=\"authorization_denied\""),
         "metrics should include classified api key signal");
}

void test_subject_containment_is_scoped_by_type_and_id() {
  clear_denylist_env();
  roche_limit::server::http::reset_containment_state_for_tests();
  roche_limit::server::http::initialize_containment_config(
      roche_limit::server::http::ContainmentConfig{
          .deny_burst_window_seconds = 60,
          .deny_burst_threshold = 2,
          .quarantine_seconds = 120,
      });
  const auto api_key_subject = roche_limit::server::http::ContainmentSubject{
      .type = "api_key",
      .id = "7",
  };
  const auto session_same_id = roche_limit::server::http::ContainmentSubject{
      .type = "session",
      .id = "7",
  };
  const auto api_key_other_id = roche_limit::server::http::ContainmentSubject{
      .type = "api_key",
      .id = "8",
  };

  roche_limit::server::http::record_containment_signal_for_subject(
      api_key_subject, "auth", "deny", "insufficient_level");
  roche_limit::server::http::record_containment_signal_for_subject(
      api_key_subject, "auth", "deny", "insufficient_level");

  expect(!roche_limit::server::http::containment_decision_for_subject(
              api_key_subject)
              .allowed,
         "api key subject should be quarantined");
  expect(roche_limit::server::http::containment_decision_for_subject(
             session_same_id)
             .allowed,
         "same numeric id with different subject type should not be quarantined");
  expect(roche_limit::server::http::containment_decision_for_subject(
             api_key_other_id)
             .allowed,
         "different id with same subject type should not be quarantined");
}

void test_manual_denylist() {
  clear_denylist_env();
  roche_limit::server::http::reset_containment_state_for_tests();
  setenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_SESSION_IDS", "7, 9", 1);
  roche_limit::server::http::initialize_containment_config(
      roche_limit::server::http::ContainmentConfig{});

  const auto decision =
      roche_limit::server::http::containment_decision_for_subject(
          roche_limit::server::http::ContainmentSubject{
              .type = "session",
              .id = "9",
          });
  expect(!decision.allowed, "manual session denylist should deny");
  expect(decision.status_code == drogon::k403Forbidden,
         "manual denylist should return 403");
  expect(decision.reason == "emergency_denylist",
         "manual denylist should expose emergency reason");

  unsetenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_SESSION_IDS");
}

void test_manual_denylist_all_subject_types() {
  clear_denylist_env();
  roche_limit::server::http::reset_containment_state_for_tests();
  setenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_IPS", "198.51.100.7", 1);
  setenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_API_KEY_IDS", "11", 1);
  setenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_SESSION_IDS", "22", 1);
  setenv("ROCHE_LIMIT_CONTAINMENT_DENYLIST_USER_IDS", "33", 1);
  roche_limit::server::http::initialize_containment_config(
      roche_limit::server::http::ContainmentConfig{});

  expect(!roche_limit::server::http::containment_decision("198.51.100.7")
              .allowed,
         "manual IP denylist should deny");
  expect(!roche_limit::server::http::containment_decision_for_subject(
              roche_limit::server::http::ContainmentSubject{
                  .type = "api_key", .id = "11"})
              .allowed,
         "manual API key denylist should deny");
  expect(!roche_limit::server::http::containment_decision_for_subject(
              roche_limit::server::http::ContainmentSubject{
                  .type = "session", .id = "22"})
              .allowed,
         "manual session denylist should deny");
  expect(!roche_limit::server::http::containment_decision_for_subject(
              roche_limit::server::http::ContainmentSubject{
                  .type = "user", .id = "33"})
              .allowed,
         "manual user denylist should deny");
  expect(roche_limit::server::http::containment_decision_for_subject(
             roche_limit::server::http::ContainmentSubject{
                 .type = "user", .id = "34"})
             .allowed,
         "unlisted user should not be denied");

  clear_denylist_env();
}

void test_subject_signal_metrics_are_counted_by_kind() {
  clear_denylist_env();
  roche_limit::server::http::reset_containment_state_for_tests();
  roche_limit::server::http::initialize_containment_config(
      roche_limit::server::http::ContainmentConfig{
          .deny_burst_window_seconds = 60,
          .deny_burst_threshold = 100,
          .quarantine_seconds = 120,
      });

  roche_limit::server::http::record_containment_signal_for_subject(
      roche_limit::server::http::ContainmentSubject{
          .type = "session", .id = "70"},
      "session_auth", "deny", "invalid_session");
  roche_limit::server::http::record_containment_signal_for_subject(
      roche_limit::server::http::ContainmentSubject{
          .type = "session", .id = "70"},
      "session_auth", "deny", "expired_session");
  roche_limit::server::http::record_containment_signal_for_subject(
      roche_limit::server::http::ContainmentSubject{
          .type = "api_key", .id = "44"},
      "auth", "deny", "insufficient_level");
  roche_limit::server::http::record_containment_signal(
      "auth", "198.51.100.55", "deny", "invalid_header");

  const auto metrics =
      roche_limit::server::http::prometheus_containment_metrics_text();
  expect(contains(metrics,
                  "roche_limit_containment_signals_total{subject_type=\"session\",signal_kind=\"session_anomaly\"} 2"),
         "session anomaly signals should be counted by subject and kind");
  expect(contains(metrics,
                  "roche_limit_containment_signals_total{subject_type=\"api_key\",signal_kind=\"authorization_denied\"} 1"),
         "api key authorization denied signal should be counted");
  expect(contains(metrics,
                  "roche_limit_containment_signals_total{subject_type=\"ip\",signal_kind=\"header_abuse\"} 1"),
         "IP header abuse signal should be counted");
}

} // namespace

int main() {
  test_deny_burst_quarantines_ip();
  test_lockdown_threshold();
  test_metrics_include_containment_state();
  test_subject_quarantine_and_signal_metrics();
  test_subject_containment_is_scoped_by_type_and_id();
  test_manual_denylist();
  test_manual_denylist_all_subject_types();
  test_subject_signal_metrics_are_counted_by_kind();
  clear_denylist_env();
  roche_limit::server::http::reset_containment_state_for_tests();

  std::cout << "roche_limit_containment_guard_tests: ok" << std::endl;
  return 0;
}
