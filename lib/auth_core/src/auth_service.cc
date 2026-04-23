#include "auth_core/auth_service.h"
#include "auth_core/access_level.h"
#include "auth_core/api_key_hasher.h"
#include "auth_core/auth_reason.h"
#include "auth_core/ip_rule_matcher.h"
#include "common/debug_log.h"

#include <algorithm>
#include <iostream>
#include <optional>
#include <sstream>

namespace roche_limit::auth_core {

AuthService::AuthService(const AuthRepository &repository)
    : repository_(repository) {}

const AuthRepository *AuthService::repository_address() const noexcept {
  return &repository_;
}

AuthResult AuthService::authorize(const RequestContext &request_context) const {
  if (roche_limit::common::verbose_logging_enabled()) {
    std::ostringstream stream;
    stream << "authorize start service=" << request_context.service_name
           << " client_ip=" << request_context.client_ip << " api_key_present="
           << (request_context.api_key.has_value() ? "yes" : "no")
           << " repository=" << static_cast<const void *>(&repository_);
    std::cerr << "[auth_core] " << stream.str() << std::endl;
  }

  if (!is_valid_ip_address(request_context.client_ip)) {
    if (roche_limit::common::verbose_logging_enabled()) {
      std::cerr << "[auth_core] invalid client ip" << std::endl;
    }
    return AuthResult{
        .decision = AuthDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::InvalidClientIp,
    };
  }
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[auth_core] client ip parsed" << std::endl;
  }

  const auto deny_match = select_most_specific_ip_match(
      request_context.client_ip, repository_.list_ip_rules(IpRuleEffect::Deny));
  if (deny_match.has_value()) {
    if (roche_limit::common::verbose_logging_enabled()) {
      std::cerr << "[auth_core] deny match id=" << deny_match->id << std::endl;
    }
    return AuthResult{
        .decision = AuthDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::IpDeny,
        .matched_ip_rule_id = deny_match->id,
    };
  }
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[auth_core] deny rules checked" << std::endl;
  }

  int ip_access_level = unknown_ip_access_level();
  std::optional<std::int64_t> matched_ip_rule_id;
  std::string reason = auth_reason::UnknownIp;

  const auto allow_match = select_most_specific_ip_match(
      request_context.client_ip,
      repository_.list_ip_rules(IpRuleEffect::Allow));
  if (allow_match.has_value()) {
    ip_access_level = 60;
    matched_ip_rule_id = allow_match->id;
    reason = auth_reason::IpAllow;
    if (roche_limit::common::verbose_logging_enabled()) {
      std::cerr << "[auth_core] allow match id=" << allow_match->id
                << std::endl;
    }

    const auto service_level = repository_.find_ip_service_level(
        allow_match->id, request_context.service_name);
    if (service_level.has_value()) {
      ip_access_level = service_level->access_level;
      reason = auth_reason::IpServiceOverride;
      if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_core] service override level=" << ip_access_level
                  << std::endl;
      }
    }
  }
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[auth_core] ip evaluation done level=" << ip_access_level
              << std::endl;
  }

  int api_key_access_level = 0;
  std::optional<std::int64_t> api_key_record_id;
  if (request_context.api_key.has_value() &&
      !request_context.api_key->empty()) {
    if (roche_limit::common::verbose_logging_enabled()) {
      std::cerr << "[auth_core] preparing api key lookup" << std::endl;
    }
    const auto key_lookup_hash = api_key_lookup_hash(*request_context.api_key);
    if (roche_limit::common::verbose_logging_enabled()) {
      std::cerr << "[auth_core] api key lookup prepared" << std::endl;
    }
    const auto api_key_record =
        repository_.find_api_key(key_lookup_hash, request_context.service_name);
    if (api_key_record.has_value() &&
        verify_api_key(*request_context.api_key, api_key_record->key_hash)) {
      api_key_access_level = api_key_record->access_level;
      api_key_record_id = api_key_record->id;
      if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_core] api key match id=" << *api_key_record_id
                  << " level=" << api_key_access_level << std::endl;
      }
      if (api_key_access_level > ip_access_level) {
        reason = auth_reason::ApiKeyElevated;
      }
    }
  }
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[auth_core] api key evaluation done level="
              << api_key_access_level << std::endl;
  }

  const int final_access_level =
      std::max(ip_access_level, api_key_access_level);
  if (roche_limit::common::verbose_logging_enabled()) {
    std::cerr << "[auth_core] final level=" << final_access_level << std::endl;
  }
  if (request_context.required_access_level.has_value() &&
      !access_level_satisfies(final_access_level,
                              request_context.required_access_level)) {
    if (roche_limit::common::verbose_logging_enabled()) {
      std::cerr << "[auth_core] insufficient level required="
                << (request_context.required_access_level.has_value()
                        ? std::to_string(*request_context.required_access_level)
                        : "-")
                << std::endl;
    }
    return AuthResult{
        .decision = AuthDecision::Deny,
        .access_level = 0,
        .reason = auth_reason::InsufficientLevel,
        .matched_ip_rule_id = matched_ip_rule_id,
        .api_key_record_id = api_key_record_id,
    };
  }
  const auto final_level = AccessLevel::from_int(final_access_level);
  if (!final_level.has_value() || !final_level->is_allowed()) {
    return AuthResult{
        .decision = AuthDecision::Deny,
        .access_level = 0,
        .reason = reason,
        .matched_ip_rule_id = matched_ip_rule_id,
        .api_key_record_id = api_key_record_id,
    };
  }

  return AuthResult{
      .decision = AuthDecision::Allow,
      .access_level = final_access_level,
      .reason = reason,
      .matched_ip_rule_id = matched_ip_rule_id,
      .api_key_record_id = api_key_record_id,
  };
}

} // namespace roche_limit::auth_core
