#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

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

struct AuditCleanupResult {
  int retention_deleted_rows{0};
  int overflow_deleted_rows{0};
};

struct AuditEventRecord {
  std::int64_t id;
  std::string created_at;
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
  std::optional<std::string> prev_event_hash;
  std::string event_hash;
};

struct AuditEventFilter {
  int limit{50};
  std::optional<std::string> event_type;
  std::optional<std::string> result;
  std::optional<std::string> service_name;
  std::optional<std::string> request_id;
  std::optional<std::string> actor_type;
  std::optional<std::string> reason;
  std::optional<std::string> client_ip;
};

class AuditRepository {
public:
  explicit AuditRepository(std::filesystem::path database_path);

  void insert_event(const NewAuditEvent &event) const;
  std::vector<AuditEventRecord>
  list_events(const AuditEventFilter &filter = {}) const;
  std::optional<AuditEventRecord> get_event(std::int64_t id) const;
  AuditCleanupResult cleanup(int retention_days, int max_rows) const;

private:
  std::filesystem::path database_path_;
};

bool audit_auth_allow_enabled();

} // namespace roche_limit::auth_store
