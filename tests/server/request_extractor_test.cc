#include "request_extractor.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using roche_limit::server::http::parse_required_access_level_header;

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

}  // namespace

int main() {
    test_missing_required_level_header();
    test_valid_required_level_header();
    test_invalid_required_level_header();
    std::cout << "roche_limit_request_extractor_tests: ok" << std::endl;
    return 0;
}
