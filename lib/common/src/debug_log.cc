#include "common/debug_log.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <string>

namespace roche_limit::common {

namespace {

std::atomic<int> g_verbose_override{-1};

bool env_verbose_enabled() {
    const char* value = std::getenv("ROCHE_LIMIT_VERBOSE");
    if (value == nullptr) {
        return false;
    }

    std::string normalized(value);
    std::transform(normalized.begin(),
                   normalized.end(),
                   normalized.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

}  // namespace

bool verbose_logging_enabled() {
    const int override_value = g_verbose_override.load();
    if (override_value >= 0) {
        return override_value == 1;
    }
    return env_verbose_enabled();
}

void set_verbose_logging_enabled(bool enabled) {
    g_verbose_override.store(enabled ? 1 : 0);
}

}  // namespace roche_limit::common
