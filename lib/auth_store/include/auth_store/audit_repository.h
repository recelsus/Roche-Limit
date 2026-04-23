#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace roche_limit::auth_store {

struct NewAuditEvent {
  std::string event_type;
  std::string actor_type;
  std::optional<std::string> actor_id;
  std::optional<std::string> target_type;
  std::optional<std::string> target_id;
  std::optional<std::string> service_name;
  std::optional<int> access_level;
  std::optional<std::string> client_ip;
  std::optional<std::string> request_id;
  std::string result;
  std::optional<std::string> reason;
  std::optional<std::string> metadata_json;
};

class AuditRepository {
public:
  explicit AuditRepository(std::filesystem::path database_path);

  void insert_event(const NewAuditEvent &event) const;
  void cleanup(int retention_days, int max_rows) const;

private:
  std::filesystem::path database_path_;
};

bool audit_auth_allow_enabled();

} // namespace roche_limit::auth_store
