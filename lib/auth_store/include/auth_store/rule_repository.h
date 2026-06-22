#pragma once

#include "auth_core/api_key_record.h"
#include "auth_core/auth_repository.h"
#include "auth_core/ip_rule_record.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace roche_limit::auth_store {

struct NewIpRule {
  std::string value_text;
  roche_limit::auth_core::AddressFamily address_family;
  roche_limit::auth_core::IpRuleType rule_type;
  std::optional<int> prefix_length;
  roche_limit::auth_core::IpRuleEffect effect;
  std::optional<std::string> note;
};

struct NewIpServiceLevel {
  std::int64_t ip_rule_id;
  std::string service_name;
  int access_level;
  std::optional<std::string> note;
};

struct NewClientCert {
  std::string fingerprint_sha256;
  std::optional<std::string> serial_number;
  std::optional<std::string> subject_dn;
  std::optional<std::string> issuer_dn;
  std::optional<std::string> not_before;
  std::optional<std::string> not_after;
  std::optional<std::string> note;
};

struct NewClientCertServiceLevel {
  std::int64_t client_cert_id;
  std::string service_name;
  int access_level;
  std::optional<std::string> note;
};

struct UpdateIpRule {
  std::optional<std::string> value_text;
  std::optional<roche_limit::auth_core::AddressFamily> address_family;
  std::optional<roche_limit::auth_core::IpRuleType> rule_type;
  std::optional<int> prefix_length;
  std::optional<roche_limit::auth_core::IpRuleEffect> effect;
  bool note_is_set{false};
  std::optional<std::string> note;
};

struct NewApiKeyRecord {
  std::string key_hash;
  std::string key_lookup_hash;
  std::optional<std::string> key_prefix;
  std::optional<std::string> service_name;
  int access_level;
  std::optional<std::string> expires_at;
  std::optional<std::string> note;
};

struct UpdateApiKeyRecord {
  bool service_name_is_set{false};
  std::optional<std::string> service_name;
  std::optional<int> access_level;
  bool expires_at_is_set{false};
  std::optional<std::string> expires_at;
  bool note_is_set{false};
  std::optional<std::string> note;
};

class RuleRepository : public roche_limit::auth_core::AuthRepository {
public:
  explicit RuleRepository(std::filesystem::path database_path);

  std::vector<roche_limit::auth_core::IpRuleRecord>
  list_ip_rules(roche_limit::auth_core::IpRuleEffect effect) const override;

  std::optional<roche_limit::auth_core::IpServiceLevelRecord>
  find_ip_service_level(std::int64_t ip_rule_id,
                        std::string_view service_name) const override;

  std::optional<roche_limit::auth_core::ApiKeyRecord>
  find_api_key(std::string_view key_lookup_hash,
               std::string_view service_name) const override;

  std::optional<roche_limit::auth_core::ApiKeyRecord>
  find_api_key_by_prefix(std::string_view key_prefix,
                         std::string_view service_name) const override;

  void note_api_key_success(std::int64_t api_key_id,
                            std::string_view client_ip) const override;
  void note_api_key_failure(std::int64_t api_key_id,
                            std::string_view client_ip) const override;
  std::optional<roche_limit::auth_core::ClientCertRecord>
  find_client_cert(std::string_view fingerprint_sha256) const override;
  std::optional<roche_limit::auth_core::ClientCertServiceLevelRecord>
  find_client_cert_service_level(std::int64_t client_cert_id,
                                 std::string_view service_name) const override;
  void note_client_cert_success(std::int64_t client_cert_id,
                                std::string_view client_ip) const override;

  std::optional<roche_limit::auth_core::IpRuleRecord>
  find_allow_ip_rule_by_value(std::string_view value_text) const;

  std::vector<roche_limit::auth_core::IpServiceLevelRecord>
  list_ip_service_levels() const;
  std::vector<roche_limit::auth_core::ApiKeyRecord> list_api_keys() const;
  std::optional<roche_limit::auth_core::ApiKeyRecord>
  get_api_key(std::int64_t api_key_id) const;
  void disable_expired_api_keys() const;

  std::int64_t insert_ip_rule(const NewIpRule &new_ip_rule) const;
  void update_ip_rule(std::int64_t ip_rule_id,
                      const UpdateIpRule &update_ip_rule) const;
  void delete_ip_rule(std::int64_t ip_rule_id) const;
  void compact_ip_ids() const;

  std::int64_t
  upsert_ip_service_level(const NewIpServiceLevel &new_ip_service_level) const;
  void delete_ip_service_level(std::int64_t ip_rule_id,
                               std::string_view service_name) const;

  std::vector<roche_limit::auth_core::ClientCertRecord>
  list_client_certs() const;
  std::vector<roche_limit::auth_core::ClientCertServiceLevelRecord>
  list_client_cert_service_levels() const;
  std::optional<roche_limit::auth_core::ClientCertRecord>
  get_client_cert(std::int64_t client_cert_id) const;
  std::int64_t insert_client_cert(const NewClientCert &new_client_cert) const;
  std::int64_t upsert_client_cert_service_level(
      const NewClientCertServiceLevel &new_client_cert_service_level) const;
  void disable_client_cert(std::int64_t client_cert_id) const;
  void enable_client_cert(std::int64_t client_cert_id) const;
  void delete_client_cert(std::int64_t client_cert_id) const;

  std::int64_t insert_api_key(const NewApiKeyRecord &new_api_key_record) const;
  void update_api_key(std::int64_t api_key_id,
                      const UpdateApiKeyRecord &update_api_key_record) const;
  void disable_api_key(std::int64_t api_key_id) const;
  void delete_api_key(std::int64_t api_key_id) const;
  void compact_api_key_ids() const;

private:
  std::filesystem::path database_path_;
};

} // namespace roche_limit::auth_store
