#include "auth_core/access_level.h"

#include <algorithm>

namespace roche_limit::auth_core {

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

int AccessLevel::value() const noexcept {
    return value_;
}

bool AccessLevel::is_allowed() const noexcept {
    return value_ > 0;
}

bool is_valid_access_level(int value) noexcept {
    return value >= AccessLevel::kMin && value <= AccessLevel::kMax;
}

bool access_level_satisfies(int granted_level, std::optional<int> required_level) noexcept {
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

}  // namespace roche_limit::auth_core
