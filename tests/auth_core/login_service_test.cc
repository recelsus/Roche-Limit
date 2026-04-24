#include "auth_core/auth_repository.h"
#include "auth_core/ip_rule_record.h"
#include "auth_core/login_repository.h"
#include "auth_core/login_request.h"
#include "auth_core/login_result.h"
#include "auth_core/login_service.h"
#include "auth_core/password_hasher.h"
#include "common/hash_util.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace {

using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::ApiKeyRecord;
using roche_limit::auth_core::AuthRepository;
using roche_limit::auth_core::CsrfTokenRecord;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleRecord;
using roche_limit::auth_core::IpRuleType;
using roche_limit::auth_core::IpServiceLevelRecord;
using roche_limit::auth_core::LoginFailureRecord;
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
  mutable std::vector<LoginFailureRecord> login_failures;
  mutable std::vector<CsrfTokenRecord> csrf_tokens;
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

  std::optional<LoginFailureRecord> find_login_failure(
      std::string_view client_ip, std::string_view username) const override {
    for (const auto& record : login_failures) {
      if (record.client_ip == client_ip && record.username == username) {
        return record;
      }
    }
    return std::nullopt;
  }

  void upsert_login_failure(std::string_view client_ip,
                            std::string_view username, int failure_count,
                            std::optional<std::string_view> locked_until)
      const override {
    for (auto& record : login_failures) {
      if (record.client_ip == client_ip && record.username == username) {
        record.failure_count = failure_count;
        record.last_failed_at = "2099-01-01 00:00:00";
        record.locked_until = locked_until.has_value()
                                  ? std::optional<std::string>(*locked_until)
                                  : std::nullopt;
        return;
      }
    }
    login_failures.push_back(LoginFailureRecord{
        .id = static_cast<std::int64_t>(login_failures.size() + 1),
        .client_ip = std::string(client_ip),
        .username = std::string(username),
        .failure_count = failure_count,
        .last_failed_at = "2099-01-01 00:00:00",
        .locked_until = locked_until.has_value()
                            ? std::optional<std::string>(*locked_until)
                            : std::nullopt,
        .created_at = "",
        .updated_at = "",
    });
  }

  void clear_login_failure(std::string_view client_ip,
                           std::string_view username) const override {
    login_failures.erase(
        std::remove_if(login_failures.begin(), login_failures.end(),
                       [&](const auto& record) {
                         return record.client_ip == client_ip &&
                                record.username == username;
                       }),
        login_failures.end());
  }

  void insert_csrf_token(std::string_view purpose, std::string_view token_hash,
                         std::string_view client_ip,
                         std::string_view expires_at) const override {
    csrf_tokens.push_back(CsrfTokenRecord{
        .id = static_cast<std::int64_t>(csrf_tokens.size() + 1),
        .purpose = std::string(purpose),
        .token_hash = std::string(token_hash),
        .client_ip = std::string(client_ip),
        .expires_at = std::string(expires_at),
        .created_at = "",
        .updated_at = "",
    });
  }

  bool has_valid_csrf_token(std::string_view purpose,
                            std::string_view token_hash,
                            std::string_view client_ip) const override {
    for (const auto& record : csrf_tokens) {
      if (record.purpose == purpose && record.token_hash == token_hash &&
          record.client_ip == client_ip && record.expires_at > "2000-01-01 00:00:00") {
        return true;
      }
    }
    return false;
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

constexpr std::string_view kLoginCsrfToken = "csrf-token";

LoginRequest make_login_request(std::string_view client_ip,
                                std::string_view username,
                                std::string_view password) {
  return LoginRequest{
      .client_ip = std::string(client_ip),
      .username = std::string(username),
      .password = std::string(password),
      .csrf_token = std::string(kLoginCsrfToken),
      .csrf_cookie_token = std::string(kLoginCsrfToken),
  };
}

void add_login_csrf_token(FakeLoginRepository& repository,
                          std::string_view client_ip) {
  repository.insert_csrf_token("login",
                               roche_limit::common::sha256_hex(kLoginCsrfToken),
                               client_ip,
                               "2099-01-01 00:00:00");
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
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auth_repository->deny_rules = {make_deny_rule("203.0.113.10")};
  auto login_repository = std::make_shared<FakeLoginRepository>();
  add_login_csrf_token(*login_repository, "203.0.113.10");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("203.0.113.10", "alice", "password"));

  expect(result.decision == LoginDecision::Deny, "ip deny should reject login");
  expect(result.reason == "ip_deny", "ip deny should set login reason");
}

void test_login_allows_valid_credentials() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 10,
      .username = "alice",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->credentials.push_back(UserCredentialRecord{
      .user_id = 10,
      .password_hash = roche_limit::auth_core::hash_password("secret-pass"),
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  add_login_csrf_token(*login_repository, "198.51.100.20");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("198.51.100.20", "alice", "secret-pass"));

  expect(result.decision == LoginDecision::Allow,
         "valid credentials should allow login");
  expect(result.user_id.has_value() && *result.user_id == 10,
         "login should return user id");
  expect(result.session_token.has_value() && !result.session_token->empty(),
         "login should create a session token");
  expect(login_repository->sessions.size() == 1,
         "login should insert a session");
  expect(login_repository->sessions.front().user_id == 10,
         "session should belong to the user");
}

void test_login_rejects_unknown_user() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  add_login_csrf_token(*login_repository, "198.51.100.20");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("198.51.100.20", "missing", "secret-pass"));

  expect(result.decision == LoginDecision::Deny,
         "unknown user should be denied");
  expect(result.reason == "invalid_credentials",
         "unknown user should look like bad credentials");
}

void test_login_rejects_legacy_password_hash_without_crash() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 11,
      .username = "legacy",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->credentials.push_back(UserCredentialRecord{
      .user_id = 11,
      .password_hash =
          "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd38a6f09a7e3c5d3f5",
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  add_login_csrf_token(*login_repository, "198.51.100.20");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("198.51.100.20", "legacy", "password"));

  expect(result.decision == LoginDecision::Deny,
         "legacy hash should be rejected");
  expect(result.reason == "invalid_credentials",
         "legacy hash should map to invalid credentials");
}

void test_login_rejects_invalid_password() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 10,
      .username = "alice",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->credentials.push_back(UserCredentialRecord{
      .user_id = 10,
      .password_hash = roche_limit::auth_core::hash_password("secret-pass"),
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  add_login_csrf_token(*login_repository, "198.51.100.20");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("198.51.100.20", "alice", "wrong-pass"));

  expect(result.decision == LoginDecision::Deny,
         "invalid password should be denied");
  expect(result.reason == "invalid_credentials",
         "invalid password should look like bad credentials");
}

void test_login_rejects_disabled_user() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 10,
      .username = "alice",
      .enabled = false,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->credentials.push_back(UserCredentialRecord{
      .user_id = 10,
      .password_hash = roche_limit::auth_core::hash_password("secret-pass"),
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  add_login_csrf_token(*login_repository, "198.51.100.20");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("198.51.100.20", "alice", "secret-pass"));

  expect(result.decision == LoginDecision::Deny,
         "disabled user should be denied");
  expect(result.reason == "invalid_credentials",
         "disabled user should look like bad credentials");
}

void test_login_rejects_invalid_csrf() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(LoginRequest{
      .client_ip = "198.51.100.20",
      .username = "alice",
      .password = "secret-pass",
      .csrf_token = std::string("invalid"),
      .csrf_cookie_token = std::string("invalid"),
  });

  expect(result.decision == LoginDecision::Deny,
         "invalid csrf should deny login");
  expect(result.reason == "invalid_csrf",
         "invalid csrf should expose csrf reason");
}

void test_login_rate_limits_after_recent_failure() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->login_failures.push_back(LoginFailureRecord{
      .id = 1,
      .client_ip = "198.51.100.20",
      .username = "alice",
      .failure_count = 3,
      .last_failed_at = "2099-01-01 00:00:00",
      .locked_until = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  add_login_csrf_token(*login_repository, "198.51.100.20");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("198.51.100.20", "alice", "secret-pass"));

  expect(result.decision == LoginDecision::Deny,
         "recent failures should rate limit login");
  expect(result.reason == "rate_limited",
         "recent failures should expose rate_limited");
  expect(result.retry_after_seconds.has_value(),
         "rate limited login should expose retry-after");
}

void test_login_locks_after_threshold() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 10,
      .username = "alice",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->credentials.push_back(UserCredentialRecord{
      .user_id = 10,
      .password_hash = roche_limit::auth_core::hash_password("secret-pass"),
      .password_updated_at = "",
      .created_at = "",
      .updated_at = "",
  });
  login_repository->login_failures.push_back(LoginFailureRecord{
      .id = 1,
      .client_ip = "198.51.100.20",
      .username = "alice",
      .failure_count = 7,
      .last_failed_at = "2000-01-01 00:00:00",
      .locked_until = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  add_login_csrf_token(*login_repository, "198.51.100.20");
  LoginService service(auth_repository, login_repository);

  const auto result = service.login(
      make_login_request("198.51.100.20", "alice", "wrong-pass"));

  expect(result.decision == LoginDecision::Deny,
         "threshold crossing should deny login");
  expect(result.reason == "locked",
         "threshold crossing should lock the login");
  expect(result.retry_after_seconds.has_value(),
         "locked login should expose retry-after");
}

void test_session_auth_uses_service_fallback() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 20,
      .username = "bob",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->service_levels.push_back(UserServiceLevelRecord{
      .id = 1,
      .user_id = 20,
      .service_name = "*",
      .access_level = 60,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->sessions.push_back(UserSessionRecord{
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
  expect(login_repository->last_seen_updated,
         "session auth using wildcard fallback should update last seen");
  expect(login_repository->last_seen_session_id.has_value() &&
             *login_repository->last_seen_session_id == 1,
         "session auth should update the matched session");
}

void test_session_auth_prefers_exact_service_over_fallback() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 21,
      .username = "carol",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->service_levels.push_back(UserServiceLevelRecord{
      .id = 1,
      .user_id = 21,
      .service_name = "*",
      .access_level = 30,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->service_levels.push_back(UserServiceLevelRecord{
      .id = 2,
      .user_id = 21,
      .service_name = "web",
      .access_level = 60,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->sessions.push_back(UserSessionRecord{
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
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->users.push_back(UserRecord{
      .id = 22,
      .username = "dave",
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  login_repository->sessions.push_back(UserSessionRecord{
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
  expect(!login_repository->last_seen_updated,
         "deny should not update last seen");
}

void test_session_auth_allows_ip_bypass_when_required_level_is_met() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auth_repository->allow_rules = {make_allow_rule(10, "198.51.100.20")};
  auth_repository->service_levels.push_back(IpServiceLevelRecord{
      .id = 1,
      .ip_rule_id = 10,
      .service_name = "web",
      .access_level = 90,
      .enabled = true,
      .note = std::nullopt,
      .created_at = "",
      .updated_at = "",
  });
  auto login_repository = std::make_shared<FakeLoginRepository>();
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
  expect(!login_repository->last_seen_updated,
         "ip bypass should not update session last seen");
}

void test_session_auth_requires_session_when_ip_level_is_insufficient() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auth_repository->allow_rules = {make_allow_rule(11, "198.51.100.21")};
  auto login_repository = std::make_shared<FakeLoginRepository>();
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
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
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
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->sessions.push_back(UserSessionRecord{
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
  expect(login_repository->session_revoked,
         "expired session should be revoked");
  expect(!login_repository->last_seen_updated,
         "expired session should not update last seen");
}

void test_logout_revokes_existing_session() {
  auto auth_repository = std::make_shared<FakeAuthRepository>();
  auto login_repository = std::make_shared<FakeLoginRepository>();
  login_repository->sessions.push_back(UserSessionRecord{
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

  expect(login_repository->session_revoked, "logout should revoke the session");
  expect(login_repository->revoked_session_hash.has_value() &&
             *login_repository->revoked_session_hash ==
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
  test_login_rejects_invalid_csrf();
  test_login_rate_limits_after_recent_failure();
  test_login_locks_after_threshold();
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
