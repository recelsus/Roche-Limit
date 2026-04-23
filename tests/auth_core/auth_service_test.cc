#include "auth_core/access_level.h"
#include "auth_core/api_key_hasher.h"
#include "auth_core/auth_repository.h"
#include "auth_core/auth_result.h"
#include "auth_core/auth_service.h"
#include "auth_core/ip_rule_record.h"
#include "auth_core/request_context.h"
#include "common/debug_log.h"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace {

using roche_limit::auth_core::access_level_satisfies;
using roche_limit::auth_core::AccessLevel;
using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::ApiKeyRecord;
using roche_limit::auth_core::AuthDecision;
using roche_limit::auth_core::AuthRepository;
using roche_limit::auth_core::AuthResult;
using roche_limit::auth_core::AuthService;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleRecord;
using roche_limit::auth_core::IpRuleType;
using roche_limit::auth_core::IpServiceLevelRecord;
using roche_limit::auth_core::is_valid_access_level;
using roche_limit::auth_core::RequestContext;

struct FakeRepository final : AuthRepository {
  std::vector<IpRuleRecord> deny_rules;
  std::vector<IpRuleRecord> allow_rules;
  std::vector<IpServiceLevelRecord> ip_service_levels;
  std::vector<ApiKeyRecord> api_keys;

  std::vector<IpRuleRecord> list_ip_rules(IpRuleEffect effect) const override {
    return effect == IpRuleEffect::Deny ? deny_rules : allow_rules;
  }

  std::optional<IpServiceLevelRecord>
  find_ip_service_level(std::int64_t ip_rule_id,
                        std::string_view service_name) const override {
    std::optional<IpServiceLevelRecord> fallback;
    for (const auto &record : ip_service_levels) {
      if (record.ip_rule_id != ip_rule_id || !record.enabled) {
        continue;
      }
      if (record.service_name == service_name) {
        return record;
      }
      if (record.service_name == "*") {
        fallback = record;
      }
    }
    return fallback;
  }

  std::optional<ApiKeyRecord>
  find_api_key(std::string_view key_lookup_hash,
               std::string_view service_name) const override {
    std::optional<ApiKeyRecord> fallback;
    for (const auto &record : api_keys) {
      if (!record.enabled || record.key_lookup_hash != key_lookup_hash) {
        continue;
      }
      if (record.service_name.has_value() &&
          *record.service_name == service_name) {
        return record;
      }
      if (!record.service_name.has_value()) {
        fallback = record;
      }
    }
    return fallback;
  }
};

[[noreturn]] void fail(std::string_view message) {
  std::cerr << "test failure: " << message << std::endl;
  std::exit(1);
}

void expect(bool condition, std::string_view message) {
  if (!condition) {
    fail(message);
  }
}

IpRuleRecord make_ip_rule(std::int64_t id, std::string value_text,
                          IpRuleEffect effect, IpRuleType rule_type,
                          int prefix_length) {
  return IpRuleRecord{
      .id = id,
      .value_text = std::move(value_text),
      .address_family = AddressFamily::IPv4,
      .rule_type = rule_type,
      .prefix_length = prefix_length,
      .effect = effect,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  };
}

ApiKeyRecord make_api_key(std::int64_t id, std::string_view plain_key,
                          std::optional<std::string> service_name,
                          int access_level) {
  return ApiKeyRecord{
      .id = id,
      .key_hash = roche_limit::auth_core::hash_api_key(plain_key),
      .key_lookup_hash = roche_limit::auth_core::api_key_lookup_hash(plain_key),
      .key_prefix = std::nullopt,
      .service_name = std::move(service_name),
      .access_level = access_level,
      .enabled = true,
      .expires_at = std::nullopt,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  };
}

void test_access_level_value_object_boundaries() {
  expect(is_valid_access_level(0), "level 0 should be valid");
  expect(is_valid_access_level(99), "level 99 should be valid");
  expect(!is_valid_access_level(-1), "negative level should be invalid");
  expect(!is_valid_access_level(100), "level above 99 should be invalid");

  const auto zero = AccessLevel::from_int(0);
  const auto sixty = AccessLevel::from_int(60);
  expect(zero.has_value(), "level 0 should create value object");
  expect(!zero->is_allowed(), "level 0 should not allow");
  expect(sixty.has_value(), "level 60 should create value object");
  expect(sixty->is_allowed(), "level 60 should allow");
  expect(sixty->value() == 60, "level value should be preserved");

  expect(access_level_satisfies(60, std::nullopt),
         "allowed level should satisfy no threshold");
  expect(access_level_satisfies(60, 60), "same level should satisfy threshold");
  expect(!access_level_satisfies(60, 90),
         "lower level should not satisfy higher threshold");
  expect(!access_level_satisfies(0, std::nullopt),
         "level 0 should not satisfy no threshold");
  expect(!access_level_satisfies(100, 1),
         "invalid granted level should not satisfy threshold");
}

void test_ip_deny_wins() {
  auto repository = std::make_shared<FakeRepository>();
  repository->deny_rules = {
      make_ip_rule(1, "203.0.113.10", IpRuleEffect::Deny, IpRuleType::Single,
                   32),
  };
  AuthService service(repository);

  const AuthResult result = service.authorize(RequestContext{
      .client_ip = "203.0.113.10",
      .service_name = "primary",
      .api_key = std::string("sample"),
  });

  expect(result.decision == AuthDecision::Deny, "ip deny should deny request");
  expect(result.access_level == 0, "ip deny should return level 0");
  expect(result.reason == "ip_deny", "ip deny should set reason");
}

void test_unknown_ip_with_api_key_elevation() {
  auto repository = std::make_shared<FakeRepository>();
  repository->api_keys = {
      make_api_key(2, "elevated-key", std::string("test"), 90),
  };
  AuthService service(repository);

  const AuthResult result = service.authorize(RequestContext{
      .client_ip = "198.51.100.20",
      .service_name = "test",
      .api_key = std::string("elevated-key"),
  });

  expect(result.decision == AuthDecision::Allow,
         "api key should allow request");
  expect(result.access_level == 90, "api key should elevate to 90");
  expect(result.api_key_record_id.has_value() && *result.api_key_record_id == 2,
         "api key id should be returned");
}

void test_legacy_api_key_hash_is_rejected_without_crash() {
  auto repository = std::make_shared<FakeRepository>();
  repository->api_keys = {
      ApiKeyRecord{
          .id = 7,
          .key_hash = "e37b1715cf8ede5c492d4838b4946c03023130aeeaae566d289d94a7"
                      "920d7a6d",
          .key_lookup_hash =
              roche_limit::auth_core::api_key_lookup_hash("legacy-key"),
          .key_prefix = std::nullopt,
          .service_name = std::string("test"),
          .access_level = 90,
          .enabled = true,
          .expires_at = std::nullopt,
          .note = std::nullopt,
          .created_at = "",
          .updated_at = "",
      },
  };
  AuthService service(repository);

  const AuthResult result = service.authorize(RequestContext{
      .client_ip = "198.51.100.20",
      .service_name = "test",
      .api_key = std::string("legacy-key"),
  });

  expect(result.decision == AuthDecision::Allow,
         "unknown ip should still use fallback allow level");
  expect(result.access_level == 10,
         "legacy api key hash should not elevate access");
  expect(!result.api_key_record_id.has_value(),
         "legacy api key hash should not match");
}

void test_allow_ip_service_override_fallback() {
  auto repository = std::make_shared<FakeRepository>();
  repository->allow_rules = {
      make_ip_rule(3, "10.0.0.0/8", IpRuleEffect::Allow, IpRuleType::Cidr, 8),
  };
  repository->ip_service_levels = {
      IpServiceLevelRecord{
          .id = 4,
          .ip_rule_id = 3,
          .service_name = "*",
          .access_level = 60,
          .enabled = true,
          .note = std::nullopt,
          .created_at = "",
          .updated_at = "",
      },
  };
  AuthService service(repository);

  const AuthResult result = service.authorize(RequestContext{
      .client_ip = "10.1.2.3",
      .service_name = "secondary",
      .api_key = std::nullopt,
  });

  expect(result.decision == AuthDecision::Allow,
         "allow ip should allow request");
  expect(result.access_level == 60, "wildcard service override should apply");
  expect(result.matched_ip_rule_id.has_value() &&
             *result.matched_ip_rule_id == 3,
         "matched ip rule id should be returned");
}

void test_allow_ip_without_service_level_defaults_to_60() {
  auto repository = std::make_shared<FakeRepository>();
  repository->allow_rules = {
      make_ip_rule(5, "192.0.2.10", IpRuleEffect::Allow, IpRuleType::Single,
                   32),
  };
  AuthService service(repository);

  const AuthResult result = service.authorize(RequestContext{
      .client_ip = "192.0.2.10",
      .service_name = "primary",
      .api_key = std::nullopt,
  });

  expect(result.decision == AuthDecision::Allow,
         "allow ip should allow request");
  expect(result.access_level == 60,
         "allow ip without override should default to 60");
}

void test_required_access_level_denies_when_below_threshold() {
  auto repository = std::make_shared<FakeRepository>();
  repository->allow_rules = {
      make_ip_rule(5, "203.0.113.44", IpRuleEffect::Allow, IpRuleType::Single,
                   32),
  };
  repository->ip_service_levels = {
      IpServiceLevelRecord{
          .id = 6,
          .ip_rule_id = 5,
          .service_name = "*",
          .access_level = 60,
          .enabled = true,
          .note = std::nullopt,
          .created_at = "",
          .updated_at = "",
      },
  };
  AuthService service(repository);

  const AuthResult result = service.authorize(RequestContext{
      .client_ip = "203.0.113.44",
      .service_name = "karing",
      .api_key = std::nullopt,
      .required_access_level = 90,
  });

  expect(result.decision == AuthDecision::Deny,
         "required level should deny request");
  expect(result.access_level == 0,
         "required level denial should return level 0");
  expect(result.reason == "insufficient_level",
         "required level should set reason");
}

void test_required_access_level_allows_exact_match() {
  auto repository = std::make_shared<FakeRepository>();
  repository->api_keys = {
      make_api_key(7, "required-level-key", std::string("karing"), 90),
  };
  AuthService service(repository);

  const AuthResult result = service.authorize(RequestContext{
      .client_ip = "198.51.100.20",
      .service_name = "karing",
      .api_key = std::string("required-level-key"),
      .required_access_level = 90,
  });

  expect(result.decision == AuthDecision::Allow,
         "exact required level should allow request");
  expect(result.access_level == 90,
         "required level allow should preserve granted level");
  expect(result.reason == "api_key_elevated",
         "api key reason should be preserved");
}

} // namespace

int main() {
  roche_limit::common::set_verbose_logging_enabled(false);
  setenv("ROCHE_LIMIT_API_KEY_PEPPER", "test-pepper", 1);

  test_access_level_value_object_boundaries();
  test_ip_deny_wins();
  test_unknown_ip_with_api_key_elevation();
  test_legacy_api_key_hash_is_rejected_without_crash();
  test_allow_ip_service_override_fallback();
  test_allow_ip_without_service_level_defaults_to_60();
  test_required_access_level_denies_when_below_threshold();
  test_required_access_level_allows_exact_match();

  std::cout << "roche_limit_auth_core_tests: ok" << std::endl;
  return 0;
}
