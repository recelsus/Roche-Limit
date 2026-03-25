#include "auth_core/api_key_hasher.h"
#include "auth_core/auth_service.h"
#include "common/debug_log.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <optional>
#include <stdexcept>
#include <string>

namespace roche_limit::auth_core {

namespace {

struct ParsedIp {
    AddressFamily family;
    std::array<std::uint8_t, 16> bytes;
    int width;
};

std::optional<ParsedIp> parse_ip(const std::string& ip_text) {
    std::array<std::uint8_t, 16> bytes{};

    if (inet_pton(AF_INET, ip_text.c_str(), bytes.data()) == 1) {
        return ParsedIp{
            .family = AddressFamily::IPv4,
            .bytes = bytes,
            .width = 32,
        };
    }

    if (inet_pton(AF_INET6, ip_text.c_str(), bytes.data()) == 1) {
        return ParsedIp{
            .family = AddressFamily::IPv6,
            .bytes = bytes,
            .width = 128,
        };
    }

    return std::nullopt;
}

int prefix_length_for_rule(const IpRuleRecord& rule) {
    if (rule.prefix_length.has_value()) {
        return *rule.prefix_length;
    }
    return rule.rule_type == IpRuleType::Single
               ? (rule.address_family == AddressFamily::IPv4 ? 32 : 128)
               : 0;
}

bool bits_match(const std::array<std::uint8_t, 16>& left,
                const std::array<std::uint8_t, 16>& right,
                int prefix_length) {
    const int full_bytes = prefix_length / 8;
    const int partial_bits = prefix_length % 8;

    if (full_bytes > 0 &&
        std::memcmp(left.data(), right.data(), static_cast<std::size_t>(full_bytes)) != 0) {
        return false;
    }

    if (partial_bits == 0) {
        return true;
    }

    const auto mask = static_cast<std::uint8_t>(0xFFu << (8 - partial_bits));
    return (left[full_bytes] & mask) == (right[full_bytes] & mask);
}

bool ip_matches_rule(const ParsedIp& client_ip, const IpRuleRecord& rule) {
    if (client_ip.family != rule.address_family) {
        return false;
    }

    const auto rule_ip = parse_ip(rule.value_text.substr(0, rule.value_text.find('/')));
    if (!rule_ip.has_value()) {
        return false;
    }

    return bits_match(client_ip.bytes, rule_ip->bytes, prefix_length_for_rule(rule));
}

std::optional<IpRuleRecord> select_most_specific_match(const ParsedIp& client_ip,
                                                       const std::vector<IpRuleRecord>& rules) {
    std::optional<IpRuleRecord> best_rule;
    int best_prefix = -1;

    for (const auto& rule : rules) {
        if (!ip_matches_rule(client_ip, rule)) {
            continue;
        }

        const int current_prefix = prefix_length_for_rule(rule);
        if (!best_rule.has_value() || current_prefix > best_prefix ||
            (current_prefix == best_prefix && rule.id < best_rule->id)) {
            best_rule = rule;
            best_prefix = current_prefix;
        }
    }

    return best_rule;
}

}  // namespace

AuthService::AuthService(const AuthRepository& repository) : repository_(repository) {}

const AuthRepository* AuthService::repository_address() const noexcept {
    return &repository_;
}

AuthResult AuthService::authorize(const RequestContext& request_context) const {
    if (roche_limit::common::verbose_logging_enabled()) {
        std::ostringstream stream;
        stream << "authorize start service=" << request_context.service_name
               << " client_ip=" << request_context.client_ip
               << " api_key_present=" << (request_context.api_key.has_value() ? "yes" : "no")
               << " repository=" << static_cast<const void*>(&repository_);
        std::cerr << "[auth_core] " << stream.str() << std::endl;
    }

    const auto parsed_client_ip = parse_ip(request_context.client_ip);
    if (!parsed_client_ip.has_value()) {
        if (roche_limit::common::verbose_logging_enabled()) {
            std::cerr << "[auth_core] invalid client ip" << std::endl;
        }
        return AuthResult{
            .decision = AuthDecision::Deny,
            .access_level = 0,
            .reason = "invalid_client_ip",
        };
    }
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_core] client ip parsed" << std::endl;
    }

    const auto deny_match =
        select_most_specific_match(*parsed_client_ip, repository_.list_ip_rules(IpRuleEffect::Deny));
    if (deny_match.has_value()) {
        if (roche_limit::common::verbose_logging_enabled()) {
            std::cerr << "[auth_core] deny match id=" << deny_match->id << std::endl;
        }
        return AuthResult{
            .decision = AuthDecision::Deny,
            .access_level = 0,
            .reason = "ip_deny",
            .matched_ip_rule_id = deny_match->id,
        };
    }
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_core] deny rules checked" << std::endl;
    }

    int ip_access_level = 30;
    std::optional<std::int64_t> matched_ip_rule_id;
    std::string reason = "unknown_ip";

    const auto allow_match = select_most_specific_match(
        *parsed_client_ip, repository_.list_ip_rules(IpRuleEffect::Allow));
    if (allow_match.has_value()) {
        ip_access_level = 90;
        matched_ip_rule_id = allow_match->id;
        reason = "ip_allow";
        if (roche_limit::common::verbose_logging_enabled()) {
            std::cerr << "[auth_core] allow match id=" << allow_match->id << std::endl;
        }

        const auto service_level =
            repository_.find_ip_service_level(allow_match->id, request_context.service_name);
        if (service_level.has_value()) {
            ip_access_level = service_level->access_level;
            reason = "ip_service_override";
            if (roche_limit::common::verbose_logging_enabled()) {
                std::cerr << "[auth_core] service override level=" << ip_access_level << std::endl;
            }
        }
    }
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_core] ip evaluation done level=" << ip_access_level << std::endl;
    }

    int api_key_access_level = 0;
    std::optional<std::int64_t> api_key_record_id;
    if (request_context.api_key.has_value() && !request_context.api_key->empty()) {
        if (roche_limit::common::verbose_logging_enabled()) {
            std::cerr << "[auth_core] hashing api key" << std::endl;
        }
        const auto key_hash = hash_api_key(*request_context.api_key);
        if (roche_limit::common::verbose_logging_enabled()) {
            std::cerr << "[auth_core] api key hashed" << std::endl;
        }
        const auto api_key_record =
            repository_.find_api_key(key_hash, request_context.service_name);
        if (api_key_record.has_value()) {
            api_key_access_level = api_key_record->access_level;
            api_key_record_id = api_key_record->id;
            if (roche_limit::common::verbose_logging_enabled()) {
                std::cerr << "[auth_core] api key match id=" << *api_key_record_id
                          << " level=" << api_key_access_level << std::endl;
            }
            if (api_key_access_level > ip_access_level) {
                reason = "api_key_elevated";
            }
        }
    }
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_core] api key evaluation done level=" << api_key_access_level << std::endl;
    }

    const int final_access_level = std::max(ip_access_level, api_key_access_level);
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_core] final level=" << final_access_level << std::endl;
    }
    if (final_access_level <= 0) {
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

}  // namespace roche_limit::auth_core
