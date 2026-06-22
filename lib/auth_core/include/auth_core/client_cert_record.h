#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace roche_limit::auth_core {

struct ClientCertRecord {
  std::int64_t id;
  std::string fingerprint_sha256;
  std::optional<std::string> serial_number;
  std::optional<std::string> subject_dn;
  std::optional<std::string> issuer_dn;
  bool enabled;
  std::optional<std::string> not_before;
  std::optional<std::string> not_after;
  std::optional<std::string> last_used_at;
  std::optional<std::string> last_used_ip;
  std::optional<std::string> note;
  std::string created_at;
  std::string updated_at;
  std::optional<std::string> revoked_at;
};

struct ClientCertServiceLevelRecord {
  std::int64_t id;
  std::int64_t client_cert_id;
  std::string service_name;
  int access_level;
  bool enabled;
  std::optional<std::string> note;
  std::string created_at;
  std::string updated_at;
};

} // namespace roche_limit::auth_core
