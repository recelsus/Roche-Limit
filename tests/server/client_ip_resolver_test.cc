#include "client_ip_resolver.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "test failure: " << message << std::endl;
        std::exit(1);
    }
}

void test_untrusted_peer_uses_peer_ip() {
    const auto trusted =
        roche_limit::server::http::parse_trusted_proxy_rules("172.18.0.0/16,127.0.0.1");
    const auto resolved = roche_limit::server::http::resolve_client_ip("203.0.113.5",
                                                                       "198.51.100.8",
                                                                       "198.51.100.9",
                                                                       trusted);
    expect(resolved == "203.0.113.5", "untrusted peer should use peer ip");
}

void test_trusted_peer_prefers_x_real_ip() {
    const auto trusted =
        roche_limit::server::http::parse_trusted_proxy_rules("172.18.0.0/16,127.0.0.1");
    const auto resolved = roche_limit::server::http::resolve_client_ip("172.18.0.3",
                                                                       "198.51.100.8",
                                                                       "198.51.100.9, 172.18.0.3",
                                                                       trusted);
    expect(resolved == "198.51.100.8", "trusted peer should prefer x-real-ip");
}

void test_trusted_peer_uses_forwarded_for_when_real_ip_missing() {
    const auto trusted =
        roche_limit::server::http::parse_trusted_proxy_rules("172.18.0.0/16,127.0.0.1");
    const auto resolved = roche_limit::server::http::resolve_client_ip("172.18.0.3",
                                                                       "",
                                                                       "198.51.100.9, 172.18.0.3",
                                                                       trusted);
    expect(resolved == "198.51.100.9",
           "trusted peer should use first forwarded-for ip when real ip is missing");
}

void test_invalid_trusted_proxy_entries_are_ignored() {
    const auto trusted =
        roche_limit::server::http::parse_trusted_proxy_rules("invalid,172.18.0.0/16,300.1.1.1");
    expect(trusted.size() == 1, "only valid trusted proxy entries should be kept");
    const auto resolved = roche_limit::server::http::resolve_client_ip("172.18.0.9",
                                                                       "198.51.100.4",
                                                                       "",
                                                                       trusted);
    expect(resolved == "198.51.100.4", "valid trusted proxy cidr should still apply");
}

void test_trusted_peer_ignores_malformed_forwarded_headers() {
    const auto trusted =
        roche_limit::server::http::parse_trusted_proxy_rules("172.18.0.0/16");
    const auto resolved = roche_limit::server::http::resolve_client_ip("172.18.0.3",
                                                                       "not-an-ip",
                                                                       "also-not-an-ip, 172.18.0.3",
                                                                       trusted);
    expect(resolved == "172.18.0.3", "malformed forwarded headers should fall back to peer ip");
}

void test_ipv6_trusted_proxy_support() {
    const auto trusted =
        roche_limit::server::http::parse_trusted_proxy_rules("fd00::/8,::1");
    const auto resolved = roche_limit::server::http::resolve_client_ip("fd00::10",
                                                                       "2001:db8::42",
                                                                       "",
                                                                       trusted);
    expect(resolved == "2001:db8::42", "trusted IPv6 proxy should allow x-real-ip");
}

}  // namespace

int main() {
    test_untrusted_peer_uses_peer_ip();
    test_trusted_peer_prefers_x_real_ip();
    test_trusted_peer_uses_forwarded_for_when_real_ip_missing();
    test_invalid_trusted_proxy_entries_are_ignored();
    test_trusted_peer_ignores_malformed_forwarded_headers();
    test_ipv6_trusted_proxy_support();
    return 0;
}
