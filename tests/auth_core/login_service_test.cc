#include "auth_core/auth_repository.h"
#include "auth_core/ip_rule_record.h"
#include "auth_core/login_repository.h"
#include "auth_core/login_request.h"
#include "auth_core/login_result.h"
#include "auth_core/login_service.h"
#include "auth_core/password_hasher.h"
#include "common/hash_util.h"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace {

using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::ApiKeyRecord;
using roche_limit::auth_core::AuthRepository;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleRecord;
using roche_limit::auth_core::IpRuleType;
using roche_limit::auth_core::IpServiceLevelRecord;
using roche_limit::auth_core::LoginDecision;
using roche_limit::auth_core::LoginRepository;
using roche_limit::auth_core::LoginRequest;
using roche_limit::auth_core::LoginService;
using roche_limit::auth_core::SessionAuthRequest;
using roche_limit::auth_core::UserCredentialRecord;
using roche_limit::auth_core::UserRecord;
using roche_limit::auth_core::UserServiceLevelRecord;
using roche_limit::auth_core::UserSessionRecord;

struct FakeAuthRepository final : AuthRepository {
  std::vector<IpRuleRecord> deny_rules;
  std::vector<IpRuleRecord> allow_rules;
  std::vector<IpServiceLevelRecord> service_levels;

  std::vector<IpRuleRecord> list_ip_rules(IpRuleEffect effect) const override {
    return effect == IpRuleEffect::Deny ? deny_rules : allow_rules;
  }
  std::optional<IpServiceLevelRecord>
  find_ip_service_level(std::int64_t ip_rule_id,
                        std::string_view service_name) const override {
    std::optional<IpServiceLevelRecord> fallback;
    for (const auto &record : service_levels) {
      if (!record.enabled || record.ip_rule_id != ip_rule_id) {
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
  std::optional<ApiKeyRecord> find_api_key(std::string_view,
                                           std::string_view) const override {
    return std::nullopt;
  }
};

struct FakeLoginRepository final : LoginRepository {
  std::vector<UserRecord> users;
  std::vector<UserCredentialRecord> credentials;
  std::vector<UserServiceLevelRecord> service_levels;
  mutable std::vector<UserSessionRecord> sessions;
  mutable std::int64_t next_session_id{1};
  mutable bool last_seen_updated{false};
  mutable bool session_revoked{false};
  mutable std::optional<std::int64_t> last_seen_session_id;
  mutable std::optional<std::string> revoked_session_hash;

  std::optional<UserRecord>
  find_enabled_user_by_username(std::string_view username) const override {
    for (const auto &user : users) {
      if (user.enabled && user.username == username) {
        return user;
      }
    }
    return std::nullopt;
  }

  std::optional<UserRecord>
  find_enabled_user_by_id(std::int64_t user_id) const override {
    for (const auto &user : users) {
      if (user.enabled && user.id == user_id) {
        return user;
      }
    }
    return std::nullopt;
  }

  std::optional<UserCredentialRecord>
  find_user_credential(std::int64_t user_id) const override {
    for (const auto &credential : credentials) {
      if (credential.user_id == user_id) {
        return credential;
      }
    }
    return std::nullopt;
  }

  std::optional<UserServiceLevelRecord>
  find_user_service_level(std::int64_t user_id,
                          std::string_view service_name) const override {
    std::optional<UserServiceLevelRecord> fallback;
    for (const auto &record : service_levels) {
      if (!record.enabled || record.user_id != user_id) {
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

  std::optional<UserSessionRecord>
  find_active_user_session(std::string_view session_token_hash) const override {
    for (const auto &session : sessions) {
      if (!session.revoked_at.has_value() &&
          session.session_token_hash == session_token_hash) {
        return session;
      }
    }
    return std::nullopt;
  }

  std::int64_t insert_user_session(std::int64_t user_id,
                                   std::string_view session_token_hash,
                                   std::string_view expires_at) const override {
    sessions.push_back(UserSessionRecord{
        .id = next_session_id,
        .session_token_hash = std::string(session_token_hash),
        .user_id = user_id,
        .expires_at = std::string(expires_at),
        .last_seen_at = "",
        .revoked_at = std::nullopt,
        .created_at = "",
        .updated_at = "",
    });
    return next_session_id++;
  }

  void update_user_session_last_seen(std::int64_t session_id) const override {
    last_seen_updated = true;
    last_seen_session_id = session_id;
  }

  void revoke_user_session(std::string_view session_token_hash) const override {
    session_revoked = true;
    revoked_session_hash = std::string(session_token_hash);
    for (auto &session : sessions) {
      if (session.session_token_hash == session_token_hash) {
        session.revoked_at = "2099-01-01 00:00:00";
      }
    }
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

IpRuleRecord make_deny_rule(std::string value_text) {
  return IpRuleRecord{
      .id = 1,
      .value_text = std::move(value_text),
      .address_family = AddressFamily::IPv4,
      .rule_type = IpRuleType::Single,
      .prefix_length = 32,
      .effect = IpRuleEffect::Deny,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  };
}

IpRuleRecord make_allow_rule(std::int64_t id, std::string value_text) {
  return IpRuleRecord{
      .id = id,
      .value_text = std::move(value_text),
      .address_family = AddressFamily::IPv4,
      .rule_type = IpRuleType::Single,
      .prefix_length = 32,
      .effect = IpRuleEffect::Allow,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  };
}

void test_login_rejects_ip_deny() {
  FakeAuthRepository auth_repository;
  auth_repository.deny_rules = {make_deny_rule("203.0.113.10")};
  FakeLoginRepository login_repository;
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(LoginRequest{
      .client_ip = "203.0.113.10",
      .username = "alice",
      .password = "password",
  });

  expect(result.decision == LoginDecision::Deny, "ip deny should reject login");
  expect(result.reason == "ip_deny", "ip deny should set login reason");
}

void test_login_allows_valid_credentials() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.users.push_back(UserRecord{
      .id = 10,
      .username = "alice",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.credentials.push_back(UserCredentialRecord{
      .user_id = 10,
      .password_hash = roche_limit::auth_core::hash_password("secret-pass"),
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(LoginRequest{
      .client_ip = "198.51.100.20",
      .username = "alice",
      .password = "secret-pass",
  });

  expect(result.decision == LoginDecision::Allow,
         "valid credentials should allow login");
  expect(result.user_id.has_value() && *result.user_id == 10,
         "login should return user id");
  expect(result.session_token.has_value() && !result.session_token->empty(),
         "login should create a session token");
  expect(login_repository.sessions.size() == 1,
         "login should insert a session");
  expect(login_repository.sessions.front().user_id == 10,
         "session should belong to the user");
}

void test_login_rejects_unknown_user() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(LoginRequest{
      .client_ip = "198.51.100.20",
      .username = "missing",
      .password = "secret-pass",
  });

  expect(result.decision == LoginDecision::Deny,
         "unknown user should be denied");
  expect(result.reason == "invalid_credentials",
         "unknown user should look like bad credentials");
}

void test_login_rejects_legacy_password_hash_without_crash() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.users.push_back(UserRecord{
      .id = 11,
      .username = "legacy",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.credentials.push_back(UserCredentialRecord{
      .user_id = 11,
      .password_hash =
          "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd38a6f09a7e3c5d3f5",
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(LoginRequest{
      .client_ip = "198.51.100.20",
      .username = "legacy",
      .password = "password",
  });

  expect(result.decision == LoginDecision::Deny,
         "legacy hash should be rejected");
  expect(result.reason == "invalid_credentials",
         "legacy hash should map to invalid credentials");
}

void test_login_rejects_invalid_password() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.users.push_back(UserRecord{
      .id = 10,
      .username = "alice",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.credentials.push_back(UserCredentialRecord{
      .user_id = 10,
      .password_hash = roche_limit::auth_core::hash_password("secret-pass"),
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(LoginRequest{
      .client_ip = "198.51.100.20",
      .username = "alice",
      .password = "wrong-pass",
  });

  expect(result.decision == LoginDecision::Deny,
         "invalid password should be denied");
  expect(result.reason == "invalid_credentials",
         "invalid password should look like bad credentials");
}

void test_login_rejects_disabled_user() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.users.push_back(UserRecord{
      .id = 10,
      .username = "alice",
      .enabled = false,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.credentials.push_back(UserCredentialRecord{
      .user_id = 10,
      .password_hash = roche_limit::auth_core::hash_password("secret-pass"),
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(LoginRequest{
      .client_ip = "198.51.100.20",
      .username = "alice",
      .password = "secret-pass",
  });

  expect(result.decision == LoginDecision::Deny,
         "disabled user should be denied");
  expect(result.reason == "invalid_credentials",
         "disabled user should look like bad credentials");
}

void test_session_auth_uses_service_fallback() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.users.push_back(UserRecord{
      .id = 20,
      .username = "bob",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.service_levels.push_back(UserServiceLevelRecord{
      .id = 1,
      .user_id = 20,
      .service_name = "*",
      .access_level = 60,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.sessions.push_back(UserSessionRecord{
      .id = 1,
      .session_token_hash = roche_limit::common::sha256_hex("session-token"),
      .user_id = 20,
      .expires_at = "2099-01-01 00:00:00",
      .last_seen_at = "",
      .revoked_at = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.20",
      .service_name = "secondary",
      .required_access_level = 60,
      .session_token = std::string("session-token"),
  });

  expect(result.decision == LoginDecision::Allow,
         "session auth should allow fallback level");
  expect(result.access_level == 60, "fallback service level should be applied");
  expect(login_repository.last_seen_updated,
         "session auth using wildcard fallback should update last seen");
  expect(login_repository.last_seen_session_id.has_value() &&
             *login_repository.last_seen_session_id == 1,
         "session auth should update the matched session");
}

void test_session_auth_prefers_exact_service_over_fallback() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.users.push_back(UserRecord{
      .id = 21,
      .username = "carol",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.service_levels.push_back(UserServiceLevelRecord{
      .id = 1,
      .user_id = 21,
      .service_name = "*",
      .access_level = 30,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.service_levels.push_back(UserServiceLevelRecord{
      .id = 2,
      .user_id = 21,
      .service_name = "web",
      .access_level = 60,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.sessions.push_back(UserSessionRecord{
      .id = 1,
      .session_token_hash = roche_limit::common::sha256_hex("session-token"),
      .user_id = 21,
      .expires_at = "2099-01-01 00:00:00",
      .last_seen_at = "",
      .revoked_at = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.20",
      .service_name = "web",
      .required_access_level = 60,
      .session_token = std::string("session-token"),
  });

  expect(result.decision == LoginDecision::Allow,
         "exact service level should allow");
  expect(result.access_level == 60,
         "exact service level should override wildcard");
}

void test_session_auth_denies_when_no_matching_service_level_exists() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.users.push_back(UserRecord{
      .id = 22,
      .username = "dave",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository.sessions.push_back(UserSessionRecord{
      .id = 1,
      .session_token_hash = roche_limit::common::sha256_hex("session-token"),
      .user_id = 22,
      .expires_at = "2099-01-01 00:00:00",
      .last_seen_at = "",
      .revoked_at = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.20",
      .service_name = "web",
      .required_access_level = 60,
      .session_token = std::string("session-token"),
  });

  expect(result.decision == LoginDecision::Deny,
         "missing service level should deny");
  expect(result.reason == "insufficient_level",
         "missing service level should map to insufficient level");
  expect(!login_repository.last_seen_updated,
         "deny should not update last seen");
}

void test_session_auth_allows_ip_bypass_when_required_level_is_met() {
  FakeAuthRepository auth_repository;
  auth_repository.allow_rules = {make_allow_rule(10, "198.51.100.20")};
  auth_repository.service_levels.push_back(IpServiceLevelRecord{
      .id = 1,
      .ip_rule_id = 10,
      .service_name = "web",
      .access_level = 90,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  FakeLoginRepository login_repository;
  LoginService service(auth_repository, login_repository);

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.20",
      .service_name = "web",
      .required_access_level = 60,
      .session_token = std::nullopt,
  });

  expect(result.decision == LoginDecision::Allow,
         "matching ip level should bypass session");
  expect(result.access_level == 90, "ip bypass should return the ip level");
  expect(result.reason == "ip_service_override",
         "ip bypass should expose ip reason");
  expect(!login_repository.last_seen_updated,
         "ip bypass should not update session last seen");
}

void test_session_auth_requires_session_when_ip_level_is_insufficient() {
  FakeAuthRepository auth_repository;
  auth_repository.allow_rules = {make_allow_rule(11, "198.51.100.21")};
  FakeLoginRepository login_repository;
  LoginService service(auth_repository, login_repository);

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.21",
      .service_name = "web",
      .required_access_level = 90,
      .session_token = std::nullopt,
  });

  expect(result.decision == LoginDecision::Deny,
         "insufficient ip level should require session");
  expect(result.reason == "missing_session",
         "request should continue into session validation");
}

void test_session_auth_rejects_invalid_session() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  LoginService service(auth_repository, login_repository);

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.20",
      .service_name = "web",
      .required_access_level = 60,
      .session_token = std::string("missing-session"),
  });

  expect(result.decision == LoginDecision::Deny,
         "unknown session should be denied");
  expect(result.reason == "invalid_session",
         "unknown session should report invalid_session");
}

void test_session_auth_rejects_expired_session() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.sessions.push_back(UserSessionRecord{
      .id = 1,
      .session_token_hash = roche_limit::common::sha256_hex("session-token"),
      .user_id = 22,
      .expires_at = "2000-01-01 00:00:00",
      .last_seen_at = "",
      .revoked_at = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.20",
      .service_name = "web",
      .required_access_level = 60,
      .session_token = std::string("session-token"),
  });

  expect(result.decision == LoginDecision::Deny,
         "expired session should be denied");
  expect(result.reason == "expired_session",
         "expired session should report expired_session");
  expect(login_repository.session_revoked, "expired session should be revoked");
  expect(!login_repository.last_seen_updated,
         "expired session should not update last seen");
}

void test_logout_revokes_existing_session() {
  FakeAuthRepository auth_repository;
  FakeLoginRepository login_repository;
  login_repository.sessions.push_back(UserSessionRecord{
      .id = 1,
      .session_token_hash = roche_limit::common::sha256_hex("session-token"),
      .user_id = 22,
      .expires_at = "2099-01-01 00:00:00",
      .last_seen_at = "",
      .revoked_at = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  LoginService service(auth_repository, login_repository);

  service.logout("session-token");

  expect(login_repository.session_revoked, "logout should revoke the session");
  expect(login_repository.revoked_session_hash.has_value() &&
             *login_repository.revoked_session_hash ==
                 roche_limit::common::sha256_hex("session-token"),
         "logout should revoke by hashed token");

  const auto result = service.authorize_session(SessionAuthRequest{
      .client_ip = "198.51.100.20",
      .service_name = "web",
      .required_access_level = 60,
      .session_token = std::string("session-token"),
  });

  expect(result.decision == LoginDecision::Deny,
         "revoked session should no longer authorize");
  expect(result.reason == "invalid_session",
         "revoked session should be treated as invalid");
}

} // namespace

int main() {
  test_login_rejects_ip_deny();
  test_login_allows_valid_credentials();
  test_login_rejects_unknown_user();
  test_login_rejects_legacy_password_hash_without_crash();
  test_login_rejects_invalid_password();
  test_login_rejects_disabled_user();
  test_session_auth_uses_service_fallback();
  test_session_auth_prefers_exact_service_over_fallback();
  test_session_auth_denies_when_no_matching_service_level_exists();
  test_session_auth_allows_ip_bypass_when_required_level_is_met();
  test_session_auth_requires_session_when_ip_level_is_insufficient();
  test_session_auth_rejects_invalid_session();
  test_session_auth_rejects_expired_session();
  test_logout_revokes_existing_session();
  std::cout << "roche_limit_login_service_tests: ok" << std::endl;
  return 0;
}
