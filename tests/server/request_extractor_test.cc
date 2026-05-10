#include "request_extractor.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using roche_limit::server::http::parse_required_access_level_header;
using roche_limit::server::http::forwarded_client_ip_headers_conflict;
using roche_limit::server::http::forwarded_for_chain_is_valid;
using roche_limit::server::http::has_multiple_single_value_header_values;
using roche_limit::server::http::is_valid_target_service_name;

[[noreturn]] void fail(std::string_view message) {
    std::cerr << "test failure: " << message << std::endl;
    std::exit(1);
}

void expect(bool condition, std::string_view message) {
    if (!condition) {
        fail(message);
    }
}

void test_missing_required_level_header() {
    const auto parsed = parse_required_access_level_header("");
    expect(!parsed.present, "missing header should not be marked present");
    expect(parsed.valid, "missing header should not be invalid");
    expect(!parsed.value.has_value(), "missing header should not have value");
}

void test_valid_required_level_header() {
    const auto parsed = parse_required_access_level_header(" 90 ");
    expect(parsed.present, "valid header should be marked present");
    expect(parsed.valid, "valid header should be marked valid");
    expect(parsed.value.has_value() && *parsed.value == 90,
           "valid header should parse integer value");
}

void test_invalid_required_level_header() {
    const auto parsed = parse_required_access_level_header("invalid");
    expect(parsed.present, "invalid header should still be marked present");
    expect(!parsed.valid, "invalid header should be marked invalid");
    expect(!parsed.value.has_value(), "invalid header should not expose value");
}

void test_required_level_rejects_out_of_range_and_multiple_values() {
    const auto too_high = parse_required_access_level_header("100");
    expect(too_high.present, "out of range header should be present");
    expect(!too_high.valid, "out of range header should be invalid");

    const auto duplicated = parse_required_access_level_header("10, 90");
    expect(duplicated.present, "multiple required level values should be present");
    expect(!duplicated.valid, "multiple required level values should be invalid");

    const auto negative = parse_required_access_level_header("-1");
    expect(negative.present, "negative required level should be present");
    expect(!negative.valid, "negative required level should be invalid");
}

void test_target_service_name_validation() {
    expect(is_valid_target_service_name("admin-api.v1"),
           "normal service names should be valid");
    expect(is_valid_target_service_name("tenant/a:blue"),
           "service names may include path-like scoped separators");
    expect(!is_valid_target_service_name(""),
           "empty service name should be invalid");
    expect(!is_valid_target_service_name("../admin"),
           "service name should not allow path traversal style names");
    expect(!is_valid_target_service_name("/admin"),
           "service name should not allow leading slash");
    expect(!is_valid_target_service_name("admin/"),
           "service name should not allow trailing slash");
    expect(!is_valid_target_service_name("admin api"),
           "service name should not allow whitespace");
    expect(!is_valid_target_service_name("admin,api"),
           "service name should not allow comma-separated values");
}

void test_single_value_header_multiple_values() {
    expect(!has_multiple_single_value_header_values("admin"),
           "single header value should be accepted");
    expect(has_multiple_single_value_header_values("admin,other"),
           "comma-separated single-value header should be rejected");
    expect(has_multiple_single_value_header_values("Bearer a, Bearer b"),
           "comma-separated authorization values should be rejected");
}

void test_forwarded_client_ip_conflict_detection() {
    expect(forwarded_client_ip_headers_conflict("198.51.100.8",
                                               "198.51.100.9, 172.18.0.3"),
           "different x-real-ip and forwarded-for client IPs should conflict");
    expect(!forwarded_client_ip_headers_conflict("198.51.100.8",
                                                "198.51.100.8, 172.18.0.3"),
           "matching forwarded client IPs should not conflict");
    expect(!forwarded_client_ip_headers_conflict("not-an-ip",
                                                "198.51.100.8"),
           "malformed x-real-ip should not be treated as a conflict");
}

void test_forwarded_for_chain_validation() {
    expect(forwarded_for_chain_is_valid("198.51.100.8"),
           "single forwarded-for IP should be valid");
    expect(forwarded_for_chain_is_valid("198.51.100.8, 172.18.0.3"),
           "comma-separated valid forwarded-for chain should be valid");
    expect(!forwarded_for_chain_is_valid("198.51.100.8, not-an-ip"),
           "malformed forwarded-for chain should be invalid");
    expect(!forwarded_for_chain_is_valid("198.51.100.8,"),
           "empty forwarded-for chain segment should be invalid");
    expect(!forwarded_for_chain_is_valid("198.51.100.8, , 172.18.0.3"),
           "blank forwarded-for chain segment should be invalid");
}

}  // namespace

int main() {
    test_missing_required_level_header();
    test_valid_required_level_header();
    test_invalid_required_level_header();
    test_required_level_rejects_out_of_range_and_multiple_values();
    test_target_service_name_validation();
    test_single_value_header_multiple_values();
    test_forwarded_client_ip_conflict_detection();
    test_forwarded_for_chain_validation();
    std::cout << "roche_limit_request_extractor_tests: ok" << std::endl;
    return 0;
}
