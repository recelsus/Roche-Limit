#include "request_observability.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {

using roche_limit::server::http::next_request_id;
using roche_limit::server::http::prometheus_metrics_text;
using roche_limit::server::http::record_auth_request;

[[noreturn]] void fail(std::string_view message) {
    std::cerr << "test failure: " << message << std::endl;
    std::exit(1);
}

void expect(bool condition, std::string_view message) {
    if (!condition) {
        fail(message);
    }
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

void test_request_ids_are_issued() {
    const std::string first = next_request_id();
    const std::string second = next_request_id();

    expect(first.rfind("rl-", 0) == 0, "request id should use rl prefix");
    expect(second.rfind("rl-", 0) == 0, "request id should use rl prefix");
    expect(first != second, "request ids should be unique");
}

void test_prometheus_metrics_include_auth_counters() {
    record_auth_request("auth", "allow", "unknown_ip");
    record_auth_request("auth", "allow", "unknown_ip");
    record_auth_request("session", "deny", "missing_session");

    const std::string metrics = prometheus_metrics_text();
    expect(contains(metrics, "# TYPE roche_limit_auth_requests_total counter"),
           "auth request metric type should be present");
    expect(contains(metrics,
                    "roche_limit_auth_requests_total{endpoint=\"auth\",result=\"allow\",reason=\"unknown_ip\"} 2"),
           "auth allow counter should be present");
    expect(contains(metrics,
                    "roche_limit_auth_requests_total{endpoint=\"session\",result=\"deny\",reason=\"missing_session\"} 1"),
           "session deny counter should be present");
    expect(contains(metrics, "roche_limit_request_ids_issued_total"),
           "request id counter should be present");
}

}  // namespace

int main() {
    test_request_ids_are_issued();
    test_prometheus_metrics_include_auth_counters();

    std::cout << "roche_limit_request_observability_tests: ok" << std::endl;
    return 0;
}
