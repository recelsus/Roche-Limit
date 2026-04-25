#include "auth_core/access_level.h"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <system_error>

namespace roche_limit::auth_core {

namespace {

int env_access_level_or_default(const char *name, int fallback) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }

  const std::string_view text(value);
  int parsed = 0;
  const auto *begin = text.data();
  const auto *end = begin + text.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end ||
      !is_valid_access_level(parsed)) {
    std::cerr << "invalid " << name << "; using " << fallback << std::endl;
    return fallback;
  }
  return parsed;
}

} // namespace

AccessLevel::AccessLevel(int value) noexcept : value_(value) {}

std::optional<AccessLevel> AccessLevel::from_int(int value) noexcept {
  if (!is_valid_access_level(value)) {
    return std::nullopt;
  }
  return AccessLevel(value);
}

AccessLevel AccessLevel::clamp(int value) noexcept {
  return AccessLevel(std::clamp(value, kMin, kMax));
}

int AccessLevel::value() const noexcept { return value_; }

bool AccessLevel::is_allowed() const noexcept { return value_ > 0; }

bool is_valid_access_level(int value) noexcept {
  return value >= AccessLevel::kMin && value <= AccessLevel::kMax;
}

bool access_level_satisfies(int granted_level,
                            std::optional<int> required_level) noexcept {
  const auto granted = AccessLevel::from_int(granted_level);
  if (!granted.has_value() || !granted->is_allowed()) {
    return false;
  }
  if (!required_level.has_value()) {
    return true;
  }
  const auto required = AccessLevel::from_int(*required_level);
  return required.has_value() && granted->value() >= required->value();
}

int unknown_ip_access_level() {
  constexpr int kDefaultUnknownIpLevel = 10;
  return env_access_level_or_default("ROCHE_LIMIT_UNKNOWN_IP_LEVEL",
                                     kDefaultUnknownIpLevel);
}

int shared_ip_allow_access_level() {
  constexpr int kDefaultSharedIpAllowLevel = 10;
  return env_access_level_or_default("ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL",
                                     kDefaultSharedIpAllowLevel);
}

int default_api_key_access_level() {
  constexpr int kDefaultApiKeyLevel = 10;
  return env_access_level_or_default("ROCHE_LIMIT_DEFAULT_API_KEY_LEVEL",
                                     kDefaultApiKeyLevel);
}

} // namespace roche_limit::auth_core
