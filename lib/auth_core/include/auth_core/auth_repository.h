#pragma once

#include "api_key_record.h"
#include "ip_rule_record.h"

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace roche_limit::auth_core {

class AuthRepository {
public:
  virtual ~AuthRepository() = default;

  virtual std::vector<IpRuleRecord>
  list_ip_rules(IpRuleEffect effect) const = 0;

  virtual std::optional<IpServiceLevelRecord>
  find_ip_service_level(std::int64_t ip_rule_id,
                        std::string_view service_name) const = 0;

  virtual std::optional<ApiKeyRecord>
  find_api_key(std::string_view key_lookup_hash,
               std::string_view service_name) const = 0;

  virtual std::optional<ApiKeyRecord>
  find_api_key_by_prefix(std::string_view key_prefix,
                         std::string_view service_name) const = 0;

  virtual void note_api_key_success(std::int64_t api_key_id,
                                    std::string_view client_ip) const = 0;

  virtual void note_api_key_failure(std::int64_t api_key_id,
                                    std::string_view client_ip) const = 0;
};

} // namespace roche_limit::auth_core
