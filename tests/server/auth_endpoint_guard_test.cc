#include "auth_endpoint_guard.h"

#include <drogon/HttpRequest.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {

void expect(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << "test failure: " << message << std::endl;
    std::exit(1);
  }
}

drogon::HttpRequestPtr make_get_request() {
  auto request = drogon::HttpRequest::newHttpRequest();
  request->setMethod(drogon::Get);
  request->setPath("/auth");
  request->addHeader("Host", "roche-limit.internal");
  return request;
}

drogon::HttpRequestPtr make_post_request() {
  auto request = drogon::HttpRequest::newHttpRequest();
  request->setMethod(drogon::Post);
  request->setPath("/login");
  request->addHeader("Host", "roche-limit.internal");
  return request;
}

void test_host_validation() {
  using roche_limit::server::http::is_valid_host_header;

  expect(is_valid_host_header("roche-limit.internal"),
         "normal host should be valid");
  expect(is_valid_host_header("127.0.0.1:8080"),
         "host with port should be valid");
  expect(!is_valid_host_header("bad host"),
         "host with whitespace should be invalid");
  expect(!is_valid_host_header("example.com/admin"),
         "host with slash should be invalid");
  expect(!is_valid_host_header("a.example,b.example"),
         "comma-joined host should be invalid");
}

void test_forwarded_proto_validation() {
  using roche_limit::server::http::is_valid_forwarded_proto_header;

  expect(is_valid_forwarded_proto_header(""),
         "missing forwarded proto should be valid");
  expect(is_valid_forwarded_proto_header("https"),
         "https forwarded proto should be valid");
  expect(!is_valid_forwarded_proto_header("ftp"),
         "unexpected forwarded proto should be invalid");
  expect(!is_valid_forwarded_proto_header("https,http"),
         "comma-joined forwarded proto should be invalid");
}

void test_rejects_unsupported_method() {
  unsetenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  roche_limit::server::http::initialize_auth_endpoint_guard_config(
      roche_limit::server::http::AuthEndpointGuardConfig{});
  auto request = make_get_request();
  request->setMethod(drogon::Post);

  const auto result =
      roche_limit::server::http::guard_auth_endpoint_request(request, "auth",
                                                             "127.0.0.1");
  expect(!result.allowed, "POST auth request should be rejected");
  expect(result.status_code == drogon::k405MethodNotAllowed,
         "unsupported method should return 405");
}

void test_rejects_oversized_body() {
  unsetenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  roche_limit::server::http::initialize_auth_endpoint_guard_config(
      roche_limit::server::http::AuthEndpointGuardConfig{
          .max_body_bytes = 0,
      });
  auto request = make_get_request();
  request->setBody("unexpected");

  const auto result =
      roche_limit::server::http::guard_auth_endpoint_request(request, "auth",
                                                             "127.0.0.1");
  expect(!result.allowed, "GET auth body should be rejected by default");
  expect(result.status_code == drogon::k413RequestEntityTooLarge,
         "oversized body should return 413");
}

void test_generic_guard_allows_post_body_with_endpoint_limit() {
  unsetenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  roche_limit::server::http::reset_auth_endpoint_rate_limits_for_tests();
  roche_limit::server::http::initialize_auth_endpoint_guard_config(
      roche_limit::server::http::AuthEndpointGuardConfig{});

  auto request = make_post_request();
  request->setBody("username=alice&password=secret");

  const auto result = roche_limit::server::http::guard_endpoint_request(
      request, "login", "127.0.0.1",
      roche_limit::server::http::EndpointGuardOptions{
          .allowed_method = drogon::Post,
          .max_body_bytes = 1024,
          .max_requests_per_window = 10,
      });
  expect(result.allowed, "generic guard should allow bounded POST body");
}

void test_public_mode_rejects_forwarded_proto_http() {
  setenv("ROCHE_LIMIT_DEPLOYMENT_MODE", "public", 1);
  roche_limit::server::http::initialize_auth_endpoint_guard_config(
      roche_limit::server::http::AuthEndpointGuardConfig{});

  auto request = make_get_request();
  request->addHeader("X-Forwarded-Proto", "http");

  const auto result =
      roche_limit::server::http::guard_auth_endpoint_request(request, "auth",
                                                             "127.0.0.1");
  expect(!result.allowed,
         "public mode should reject insecure forwarded proto");
  expect(result.status_code == drogon::k400BadRequest,
         "insecure forwarded proto should return 400");

  unsetenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
}

void test_rate_limit() {
  unsetenv("ROCHE_LIMIT_DEPLOYMENT_MODE");
  roche_limit::server::http::reset_auth_endpoint_rate_limits_for_tests();
  roche_limit::server::http::initialize_auth_endpoint_guard_config(
      roche_limit::server::http::AuthEndpointGuardConfig{
          .rate_limit_window_seconds = 60,
          .auth_max_requests_per_window = 1,
      });

  auto first = make_get_request();
  auto second = make_get_request();
  const auto first_result =
      roche_limit::server::http::guard_auth_endpoint_request(first, "auth",
                                                             "127.0.0.1");
  const auto second_result =
      roche_limit::server::http::guard_auth_endpoint_request(second, "auth",
                                                             "127.0.0.1");

  expect(first_result.allowed, "first request in window should be allowed");
  expect(!second_result.allowed, "second request in window should be limited");
  expect(second_result.status_code == drogon::k429TooManyRequests,
         "rate-limited request should return 429");
  expect(second_result.retry_after_seconds.has_value(),
         "rate-limited request should include retry-after");

  roche_limit::server::http::reset_auth_endpoint_rate_limits_for_tests();
}

} // namespace

int main() {
  test_host_validation();
  test_forwarded_proto_validation();
  test_rejects_unsupported_method();
  test_rejects_oversized_body();
  test_generic_guard_allows_post_body_with_endpoint_limit();
  test_public_mode_rejects_forwarded_proto_http();
  test_rate_limit();

  std::cout << "roche_limit_auth_endpoint_guard_tests: ok" << std::endl;
  return 0;
}
