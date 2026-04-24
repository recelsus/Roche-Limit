#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace roche_limit::auth_core {

struct ApiKeyRecord {
  std::int64_t id;
  std::string key_hash;
  std::string key_lookup_hash;
  std::optional<std::string> key_prefix;
  std::optional<std::string> service_name;
  int access_level;
  bool enabled;
  std::optional<std::string> expires_at;
  std::optional<std::string> last_used_at;
  std::optional<std::string> last_used_ip;
  std::optional<std::string> last_failed_at;
  int failed_attempts;
  std::optional<std::string> note;
  std::string created_at;
  std::string updated_at;
};

} // namespace roche_limit::auth_core
