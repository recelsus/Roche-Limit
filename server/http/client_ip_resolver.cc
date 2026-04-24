#include "client_ip_resolver.h"

#include "auth_core/ip_rule_matcher.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace roche_limit::server::http {

namespace {

ProxyAccessConfig g_proxy_access_config;

std::string trim(std::string value) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

std::optional<roche_limit::auth_core::IpRuleRecord> parse_proxy_rule(
    std::string value_text,
    std::int64_t id) {
    value_text = trim(std::move(value_text));
    if (value_text.empty()) {
        return std::nullopt;
    }

    const auto slash = value_text.find('/');
    const auto host_text = slash == std::string::npos
                               ? value_text
                               : value_text.substr(0, slash);
    if (!roche_limit::auth_core::is_valid_ip_address(host_text)) {
        return std::nullopt;
    }

    const auto address_family = host_text.find(':') == std::string::npos
                                    ? roche_limit::auth_core::AddressFamily::IPv4
                                    : roche_limit::auth_core::AddressFamily::IPv6;

    std::optional<int> prefix_length;
    roche_limit::auth_core::IpRuleType rule_type = roche_limit::auth_core::IpRuleType::Single;
    if (slash != std::string::npos) {
        const auto prefix_text = value_text.substr(slash + 1);
        try {
            prefix_length = std::stoi(prefix_text);
        } catch (...) {
            return std::nullopt;
        }

        const int max_prefix =
            address_family == roche_limit::auth_core::AddressFamily::IPv4 ? 32 : 128;
        if (*prefix_length < 0 || *prefix_length > max_prefix) {
            return std::nullopt;
        }
        rule_type = roche_limit::auth_core::IpRuleType::Cidr;
    }

    return roche_limit::auth_core::IpRuleRecord{
        .id = id,
        .value_text = std::move(value_text),
        .address_family = address_family,
        .rule_type = rule_type,
        .prefix_length = prefix_length,
        .effect = roche_limit::auth_core::IpRuleEffect::Allow,
        .enabled = true,
        .note = std::nullopt,
        .created_at = {},
        .updated_at = {},
    };
}

struct ParsedRuleList {
    std::vector<roche_limit::auth_core::IpRuleRecord> rules;
    std::vector<std::string> invalid_tokens;
};

ParsedRuleList parse_proxy_rule_list(std::string_view rules_text) {
    ParsedRuleList parsed;
    std::size_t start = 0;
    std::int64_t id = 1;

    while (start <= rules_text.size()) {
        const auto separator = rules_text.find(',', start);
        const auto token = rules_text.substr(
            start,
            separator == std::string_view::npos ? std::string_view::npos : separator - start);
        const auto trimmed = trim(std::string(token));
        if (!trimmed.empty()) {
            if (const auto rule = parse_proxy_rule(trimmed, id); rule.has_value()) {
                parsed.rules.push_back(*rule);
                ++id;
            } else {
                parsed.invalid_tokens.push_back(trimmed);
            }
        }

        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1;
    }

    return parsed;
}

void require_valid_proxy_rule_list(std::string_view env_name,
                                   std::string_view env_value,
                                   const ParsedRuleList& parsed) {
    if (parsed.invalid_tokens.empty()) {
        return;
    }

    std::string message = std::string(env_name) + " contains invalid entries: ";
    for (std::size_t index = 0; index < parsed.invalid_tokens.size(); ++index) {
        if (index > 0) {
            message += ", ";
        }
        message += parsed.invalid_tokens[index];
    }
    message += " (input: " + std::string(env_value) + ")";
    throw std::runtime_error(message);
}

std::string extract_forwarded_ip(std::string_view forwarded_for_header) {
    if (forwarded_for_header.empty()) {
        return {};
    }

    const auto separator = forwarded_for_header.find(',');
    const auto forwarded_ip = trim(std::string(forwarded_for_header.substr(0, separator)));
    if (!roche_limit::auth_core::is_valid_ip_address(forwarded_ip)) {
        return {};
    }
    return forwarded_ip;
}

bool is_trusted_proxy(std::string_view peer_ip,
                      const std::vector<roche_limit::auth_core::IpRuleRecord>& trusted_proxy_rules) {
    if (trusted_proxy_rules.empty()) {
        return false;
    }
    return roche_limit::auth_core::select_most_specific_ip_match(peer_ip, trusted_proxy_rules).has_value();
}

}  // namespace

std::vector<roche_limit::auth_core::IpRuleRecord> parse_trusted_proxy_rules(
    std::string_view trusted_proxies_text) {
    return parse_proxy_rule_list(trusted_proxies_text).rules;
}

std::vector<roche_limit::auth_core::IpRuleRecord> load_trusted_proxy_rules_from_env() {
    const char* value = std::getenv("ROCHE_LIMIT_TRUSTED_PROXIES");
    if (value == nullptr || *value == '\0') {
        return {};
    }
    return parse_trusted_proxy_rules(value);
}

ProxyAccessConfig load_proxy_access_config_from_env() {
    ProxyAccessConfig config;

    const char* trusted_value = std::getenv("ROCHE_LIMIT_TRUSTED_PROXIES");
    if (trusted_value != nullptr && *trusted_value != '\0') {
        const auto parsed = parse_proxy_rule_list(trusted_value);
        require_valid_proxy_rule_list("ROCHE_LIMIT_TRUSTED_PROXIES",
                                      trusted_value,
                                      parsed);
        config.trusted_proxy_rules = parsed.rules;
    }

    const char* allowed_value = std::getenv("ROCHE_LIMIT_ALLOWED_PEERS");
    if (allowed_value != nullptr && *allowed_value != '\0') {
        const auto parsed = parse_proxy_rule_list(allowed_value);
        require_valid_proxy_rule_list("ROCHE_LIMIT_ALLOWED_PEERS",
                                      allowed_value,
                                      parsed);
        config.allowed_peer_rules = parsed.rules;
    } else {
        config.allowed_peer_rules = config.trusted_proxy_rules;
    }

    return config;
}

void initialize_proxy_access_config(ProxyAccessConfig config) {
    g_proxy_access_config = std::move(config);
}

const std::vector<roche_limit::auth_core::IpRuleRecord>& trusted_proxy_rules() {
    return g_proxy_access_config.trusted_proxy_rules;
}

bool is_allowed_auth_peer(std::string_view peer_ip) {
    if (g_proxy_access_config.allowed_peer_rules.empty()) {
        return true;
    }
    return roche_limit::auth_core::select_most_specific_ip_match(
               peer_ip, g_proxy_access_config.allowed_peer_rules)
        .has_value();
}

std::string resolve_client_ip(std::string_view peer_ip,
                              std::string_view real_ip_header,
                              std::string_view forwarded_for_header,
                              const std::vector<roche_limit::auth_core::IpRuleRecord>& trusted_proxy_rules) {
    const auto trimmed_peer_ip = trim(std::string(peer_ip));
    if (!is_trusted_proxy(trimmed_peer_ip, trusted_proxy_rules)) {
        return trimmed_peer_ip;
    }

    const auto real_ip = trim(std::string(real_ip_header));
    if (!real_ip.empty() && roche_limit::auth_core::is_valid_ip_address(real_ip)) {
        return real_ip;
    }

    const auto forwarded_ip = extract_forwarded_ip(forwarded_for_header);
    if (!forwarded_ip.empty()) {
        return forwarded_ip;
    }

    return trimmed_peer_ip;
}

}  // namespace roche_limit::server::http
