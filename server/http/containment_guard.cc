#include "containment_guard.h"

#include "auth_core/auth_reason.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>

namespace roche_limit::server::http {

namespace {

using Clock = std::chrono::steady_clock;

struct BurstBucket {
  Clock::time_point window_started_at{};
  int count{0};
};

ContainmentConfig g_config;
std::mutex g_mutex;
std::map<std::string, BurstBucket> g_deny_buckets;
std::map<std::string, Clock::time_point> g_quarantined_until;
std::set<std::string> g_manual_denylist;
std::map<std::pair<std::string, std::string>, std::uint64_t>
    g_signal_counts;
BurstBucket g_global_deny_bucket;
Clock::time_point g_lockdown_until{};
std::uint64_t g_quarantine_events_total{0};
std::uint64_t g_lockdown_events_total{0};

int env_int_or_default(const char *name, int fallback) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }

  const std::string_view text(value);
  int parsed = 0;
  const auto *begin = text.data();
  const auto *end = begin + text.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end || parsed < 0) {
    return fallback;
  }
  return parsed;
}

bool env_flag_or_default(const char *name, bool fallback) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }
  const std::string_view text(value);
  if (text == "1" || text == "true" || text == "yes") {
    return true;
  }
  if (text == "0" || text == "false" || text == "no") {
    return false;
  }
  return fallback;
}

std::string trim(std::string value) {
  const auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  value.erase(value.begin(),
              std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
              value.end());
  return value;
}

std::set<std::string> parse_subject_denylist(std::string_view type,
                                             const char *env_name) {
  const char *value = std::getenv(env_name);
  if (value == nullptr || *value == '\0') {
    return {};
  }

  std::set<std::string> subjects;
  const std::string_view text(value);
  std::size_t start = 0;
  while (start <= text.size()) {
    const auto separator = text.find(',', start);
    const auto token = text.substr(
        start, separator == std::string_view::npos ? std::string_view::npos
                                                   : separator - start);
    const auto id = trim(std::string(token));
    if (!id.empty()) {
      subjects.insert(std::string(type) + ":" + id);
    }
    if (separator == std::string_view::npos) {
      break;
    }
    start = separator + 1;
  }
  return subjects;
}

std::set<std::string> load_manual_denylist_from_env() {
  std::set<std::string> denylist;
  for (const auto &subject :
       parse_subject_denylist("ip", "ROCHE_LIMIT_CONTAINMENT_DENYLIST_IPS")) {
    denylist.insert(subject);
  }
  for (const auto &subject : parse_subject_denylist(
           "api_key", "ROCHE_LIMIT_CONTAINMENT_DENYLIST_API_KEY_IDS")) {
    denylist.insert(subject);
  }
  for (const auto &subject : parse_subject_denylist(
           "session", "ROCHE_LIMIT_CONTAINMENT_DENYLIST_SESSION_IDS")) {
    denylist.insert(subject);
  }
  for (const auto &subject :
       parse_subject_denylist("user", "ROCHE_LIMIT_CONTAINMENT_DENYLIST_USER_IDS")) {
    denylist.insert(subject);
  }
  return denylist;
}

std::string subject_key(const ContainmentSubject &subject) {
  return subject.type + ":" + subject.id;
}

std::string signal_kind_for_reason(std::string_view reason) {
  if (reason == roche_limit::auth_core::auth_reason::InvalidHeader ||
      reason == roche_limit::auth_core::auth_reason::ConflictingForwardedHeaders) {
    return "header_abuse";
  }
  if (reason == roche_limit::auth_core::auth_reason::InvalidCredentials ||
      reason == roche_limit::auth_core::auth_reason::InvalidCsrf ||
      reason == roche_limit::auth_core::auth_reason::Locked ||
      reason == roche_limit::auth_core::auth_reason::RateLimited) {
    return "credential_abuse";
  }
  if (reason == roche_limit::auth_core::auth_reason::InvalidSession ||
      reason == roche_limit::auth_core::auth_reason::ExpiredSession ||
      reason == roche_limit::auth_core::auth_reason::SessionRotationRequired ||
      reason == roche_limit::auth_core::auth_reason::MissingSession) {
    return "session_anomaly";
  }
  if (reason == roche_limit::auth_core::auth_reason::InsufficientLevel ||
      reason == roche_limit::auth_core::auth_reason::IpDeny ||
      reason == roche_limit::auth_core::auth_reason::ForbiddenPeer) {
    return "authorization_denied";
  }
  if (reason == roche_limit::auth_core::auth_reason::InternalError) {
    return "internal_error";
  }
  return "deny";
}

int seconds_until(Clock::time_point deadline, Clock::time_point now) {
  if (deadline <= now) {
    return 0;
  }
  return std::max<int>(
      1, static_cast<int>(
             std::chrono::duration_cast<std::chrono::seconds>(deadline - now)
                 .count()));
}

bool should_ignore_reason(std::string_view reason) {
  return reason == roche_limit::auth_core::auth_reason::Quarantined ||
         reason == roche_limit::auth_core::auth_reason::Lockdown ||
         reason == roche_limit::auth_core::auth_reason::EmergencyDenylist;
}

bool should_count_signal(std::string_view result, std::string_view reason) {
  if (should_ignore_reason(reason)) {
    return false;
  }
  return result == "deny" || result == "error";
}

bool increment_bucket(BurstBucket &bucket, Clock::time_point now,
                      std::chrono::seconds window, int threshold) {
  if (threshold <= 0) {
    return false;
  }
  if (bucket.count == 0 || now - bucket.window_started_at >= window) {
    bucket.window_started_at = now;
    bucket.count = 1;
    return false;
  }
  ++bucket.count;
  return bucket.count >= threshold;
}

} // namespace

ContainmentConfig load_containment_config_from_env() {
  return ContainmentConfig{
      .enabled = env_flag_or_default("ROCHE_LIMIT_CONTAINMENT_ENABLED", true),
      .deny_burst_window_seconds =
          env_int_or_default("ROCHE_LIMIT_CONTAINMENT_WINDOW_SECONDS", 60),
      .deny_burst_threshold =
          env_int_or_default("ROCHE_LIMIT_CONTAINMENT_DENY_THRESHOLD", 20),
      .quarantine_seconds =
          env_int_or_default("ROCHE_LIMIT_CONTAINMENT_QUARANTINE_SECONDS", 300),
      .lockdown_deny_burst_threshold = env_int_or_default(
          "ROCHE_LIMIT_CONTAINMENT_LOCKDOWN_DENY_THRESHOLD", 0),
      .lockdown_seconds =
          env_int_or_default("ROCHE_LIMIT_CONTAINMENT_LOCKDOWN_SECONDS", 300),
  };
}

void initialize_containment_config(ContainmentConfig config) {
  if (config.deny_burst_window_seconds <= 0) {
    config.deny_burst_window_seconds = 60;
  }
  if (config.quarantine_seconds <= 0) {
    config.quarantine_seconds = 300;
  }
  if (config.lockdown_seconds <= 0) {
    config.lockdown_seconds = 300;
  }
  std::lock_guard lock(g_mutex);
  g_config = config;
  g_manual_denylist = load_manual_denylist_from_env();
}

void reset_containment_state_for_tests() {
  std::lock_guard lock(g_mutex);
  g_deny_buckets.clear();
  g_quarantined_until.clear();
  g_manual_denylist.clear();
  g_signal_counts.clear();
  g_global_deny_bucket = BurstBucket{};
  g_lockdown_until = Clock::time_point{};
  g_quarantine_events_total = 0;
  g_lockdown_events_total = 0;
}

ContainmentDecision containment_decision(std::string_view client_ip) {
  return containment_decision_for_subject(ContainmentSubject{
      .type = "ip",
      .id = std::string(client_ip),
  });
}

ContainmentDecision containment_decision_for_subject(
    const ContainmentSubject &subject) {
  const auto now = Clock::now();
  std::lock_guard lock(g_mutex);
  if (!g_config.enabled) {
    return ContainmentDecision{};
  }

  const auto key = subject_key(subject);
  if (g_manual_denylist.find(key) != g_manual_denylist.end()) {
    return ContainmentDecision{
        .allowed = false,
        .status_code = drogon::k403Forbidden,
        .reason = roche_limit::auth_core::auth_reason::EmergencyDenylist,
    };
  }

  if (g_lockdown_until > now) {
    return ContainmentDecision{
        .allowed = false,
        .status_code = drogon::k503ServiceUnavailable,
        .reason = roche_limit::auth_core::auth_reason::Lockdown,
        .retry_after_seconds = seconds_until(g_lockdown_until, now),
    };
  }

  const auto quarantine = g_quarantined_until.find(key);
  if (quarantine == g_quarantined_until.end()) {
    return ContainmentDecision{};
  }
  if (quarantine->second <= now) {
    g_quarantined_until.erase(quarantine);
    return ContainmentDecision{};
  }
  return ContainmentDecision{
      .allowed = false,
      .status_code = drogon::k429TooManyRequests,
      .reason = roche_limit::auth_core::auth_reason::Quarantined,
      .retry_after_seconds = seconds_until(quarantine->second, now),
  };
}

void record_containment_signal(std::string_view,
                               std::string_view client_ip,
                               std::string_view result,
                               std::string_view reason) {
  record_containment_signal_for_subject(
      ContainmentSubject{.type = "ip", .id = std::string(client_ip)}, "",
      result, reason);
}

void record_containment_signal_for_subject(const ContainmentSubject &subject,
                                           std::string_view endpoint,
                                           std::string_view result,
                                           std::string_view reason) {
  if (subject.id.empty() || !should_count_signal(result, reason)) {
    return;
  }

  const auto now = Clock::now();
  std::lock_guard lock(g_mutex);
  if (!g_config.enabled) {
    return;
  }

  const auto key = subject_key(subject);
  const auto signal_kind = signal_kind_for_reason(reason);
  ++g_signal_counts[{subject.type, signal_kind}];

  const auto window = std::chrono::seconds(g_config.deny_burst_window_seconds);
  if (increment_bucket(g_deny_buckets[key], now, window,
                       g_config.deny_burst_threshold)) {
    g_quarantined_until[key] =
        now + std::chrono::seconds(g_config.quarantine_seconds);
    ++g_quarantine_events_total;
  }

  if (increment_bucket(g_global_deny_bucket, now, window,
                       g_config.lockdown_deny_burst_threshold)) {
    g_lockdown_until = now + std::chrono::seconds(g_config.lockdown_seconds);
    ++g_lockdown_events_total;
  }
}

std::string prometheus_containment_metrics_text() {
  const auto now = Clock::now();
  std::lock_guard lock(g_mutex);
  std::size_t active_quarantines = 0;
  std::map<std::string, std::size_t> active_by_type;
  for (const auto &[_, until] : g_quarantined_until) {
    if (until > now) {
      ++active_quarantines;
      const auto separator = _.find(':');
      const auto type = separator == std::string::npos ? std::string("unknown")
                                                       : _.substr(0, separator);
      ++active_by_type[type];
    }
  }

  std::ostringstream output;
  output << "# HELP roche_limit_quarantine_active Number of active IP "
            "quarantines.\n";
  output << "# TYPE roche_limit_quarantine_active gauge\n";
  output << "roche_limit_quarantine_active " << active_quarantines << '\n';
  output << "# HELP roche_limit_quarantine_active_by_subject Active "
            "quarantines by subject type.\n";
  output << "# TYPE roche_limit_quarantine_active_by_subject gauge\n";
  for (const auto &[type, count] : active_by_type) {
    output << "roche_limit_quarantine_active_by_subject{subject_type=\""
           << type << "\"} " << count << '\n';
  }
  output << "# HELP roche_limit_quarantine_events_total Number of quarantine "
            "events triggered by deny bursts.\n";
  output << "# TYPE roche_limit_quarantine_events_total counter\n";
  output << "roche_limit_quarantine_events_total "
         << g_quarantine_events_total << '\n';
  output << "# HELP roche_limit_lockdown_active Whether global lockdown is "
            "currently active.\n";
  output << "# TYPE roche_limit_lockdown_active gauge\n";
  output << "roche_limit_lockdown_active " << (g_lockdown_until > now ? 1 : 0)
         << '\n';
  output << "# HELP roche_limit_lockdown_events_total Number of global "
            "lockdown events triggered by deny bursts.\n";
  output << "# TYPE roche_limit_lockdown_events_total counter\n";
  output << "roche_limit_lockdown_events_total " << g_lockdown_events_total
         << '\n';
  output << "# HELP roche_limit_containment_signals_total Containment "
            "signals by subject type and signal kind.\n";
  output << "# TYPE roche_limit_containment_signals_total counter\n";
  for (const auto &[key, count] : g_signal_counts) {
    const auto &[subject_type, signal_kind] = key;
    output << "roche_limit_containment_signals_total{subject_type=\""
           << subject_type << "\",signal_kind=\"" << signal_kind << "\"} "
           << count << '\n';
  }
  return output.str();
}

} // namespace roche_limit::server::http
