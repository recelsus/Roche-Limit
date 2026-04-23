#pragma once

#include <optional>

namespace roche_limit::auth_core {

class AccessLevel {
public:
  static constexpr int kMin = 0;
  static constexpr int kMax = 99;

  static std::optional<AccessLevel> from_int(int value) noexcept;
  static AccessLevel clamp(int value) noexcept;

  int value() const noexcept;
  bool is_allowed() const noexcept;

private:
  explicit AccessLevel(int value) noexcept;

  int value_{0};
};

bool access_level_satisfies(int granted_level,
                            std::optional<int> required_level) noexcept;
bool is_valid_access_level(int value) noexcept;
int unknown_ip_access_level();

} // namespace roche_limit::auth_core
