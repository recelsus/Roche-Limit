#include "cli_support.h"

#include <arpa/inet.h>
#include <cstdlib>

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>

namespace roche_limit::cli {

using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleType;

[[noreturn]] void fail(std::string_view message) {
    throw std::runtime_error(std::string(message));
}

OptionsMap parse_options(const std::vector<std::string>& args, std::size_t start_index) {
    OptionsMap options;

    for (std::size_t index = start_index; index < args.size(); ++index) {
        const auto& current = args[index];
        if (!current.starts_with("--")) {
            fail("invalid option format");
        }

        if (index + 1 < args.size() && !args[index + 1].starts_with("--")) {
            options[current] = args[index + 1];
            ++index;
            continue;
        }

        options[current] = "true";
    }

    return options;
}

std::string require_option(const OptionsMap& options, std::string_view key) {
    const auto it = options.find(std::string(key));
    if (it == options.end()) {
        fail(std::string("missing required option: ") + std::string(key));
    }
    return it->second;
}

std::optional<std::string> optional_option(const OptionsMap& options, std::string_view key) {
    const auto it = options.find(std::string(key));
    if (it == options.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::int64_t parse_int64(std::string_view value, std::string_view name) {
    char* end = nullptr;
    const auto parsed = std::strtoll(std::string(value).c_str(), &end, 10);
    if (end == nullptr || *end != '\0') {
        fail(std::string("invalid integer for ") + std::string(name));
    }
    return parsed;
}

int parse_int(std::string_view value, std::string_view name) {
    return static_cast<int>(parse_int64(value, name));
}

std::string to_string(AddressFamily value) {
    return value == AddressFamily::IPv4 ? "ipv4" : "ipv6";
}

std::string to_string(IpRuleType value) {
    return value == IpRuleType::Single ? "single" : "cidr";
}

std::string to_string(IpRuleEffect value) {
    return value == IpRuleEffect::Allow ? "allow" : "deny";
}

std::string printable_service_name(const std::optional<std::string>& value) {
    return value.has_value() ? *value : "*";
}

std::string printable_service_name(std::string_view value) {
    return value.empty() ? "*" : std::string(value);
}

std::string bool_label(bool value) {
    return value ? "enabled" : "disabled";
}

bool experimental_cli_enabled() {
    const char* value = std::getenv("ROCHE_LIMIT_ENABLE_EXPERIMENTAL_CLI");
    if (value == nullptr) {
        return false;
    }
    const std::string text(value);
    return text == "1" || text == "true" || text == "TRUE" || text == "yes" || text == "on";
}

void require_experimental_cli(std::string_view command_name) {
    if (!experimental_cli_enabled()) {
        fail(std::string(command_name) +
             " is experimental; set ROCHE_LIMIT_ENABLE_EXPERIMENTAL_CLI=1 to enable it");
    }
}

bool looks_like_ip_or_cidr(std::string_view value) {
    return value.find('/') != std::string_view::npos || value.find('.') != std::string_view::npos ||
           value.find(':') != std::string_view::npos;
}

std::optional<std::string> parse_service_name_option(const OptionsMap& options,
                                                     std::string_view key) {
    const auto value = optional_option(options, key);
    if (!value.has_value()) {
        return std::nullopt;
    }
    if (*value == "*" || *value == "all") {
        return std::nullopt;
    }
    return value;
}

void print_table(const std::vector<std::string>& header,
                 const std::vector<std::vector<std::string>>& rows) {
    std::vector<std::size_t> widths(header.size(), 0);
    for (std::size_t index = 0; index < header.size(); ++index) {
        widths[index] = header[index].size();
    }

    for (const auto& row : rows) {
        for (std::size_t index = 0; index < row.size(); ++index) {
            widths[index] = std::max(widths[index], row[index].size());
        }
    }

    const auto print_row = [&widths](const std::vector<std::string>& row) {
        for (std::size_t index = 0; index < row.size(); ++index) {
            std::cout << std::left << std::setw(static_cast<int>(widths[index] + 2)) << row[index];
        }
        std::cout << '\n';
    };

    print_row(header);
    for (const auto& row : rows) {
        print_row(row);
    }
}

ParsedCliIp parse_cli_ip(std::string_view value) {
    const auto slash_position = value.find('/');
    const auto host_text = std::string(value.substr(0, slash_position));

    std::array<unsigned char, 16> bytes{};
    AddressFamily family;
    int full_prefix_length;
    if (inet_pton(AF_INET, host_text.c_str(), bytes.data()) == 1) {
        family = AddressFamily::IPv4;
        full_prefix_length = 32;
    } else if (inet_pton(AF_INET6, host_text.c_str(), bytes.data()) == 1) {
        family = AddressFamily::IPv6;
        full_prefix_length = 128;
    } else {
        fail("invalid ip or cidr value");
    }

    if (slash_position == std::string_view::npos) {
        return ParsedCliIp{
            .family = family,
            .rule_type = IpRuleType::Single,
            .prefix_length = full_prefix_length,
        };
    }

    const auto prefix_text = std::string(value.substr(slash_position + 1));
    const int prefix_length = parse_int(prefix_text, "cidr prefix");
    if (prefix_length < 0 || prefix_length > full_prefix_length) {
        fail("cidr prefix length is out of range");
    }

    return ParsedCliIp{
        .family = family,
        .rule_type = IpRuleType::Cidr,
        .prefix_length = prefix_length,
    };
}

std::string generate_api_key() {
    static constexpr std::string_view alphabet =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<std::size_t> distribution(0, alphabet.size() - 1);

    std::string result;
    result.reserve(32);
    for (int index = 0; index < 32; ++index) {
        result.push_back(alphabet[distribution(generator)]);
    }
    return result;
}

std::string prompt_password() {
    std::cout << "Password: " << std::flush;
    std::string password;
    std::getline(std::cin, password);
    if (password.empty()) {
        fail("password is required");
    }
    return password;
}

std::string option_or_prompt_password(const OptionsMap& options) {
    if (const auto password = optional_option(options, "--password"); password.has_value()) {
        return *password;
    }
    return prompt_password();
}

void print_usage() {
    std::cout << "Usage:\n"
              << "  roche_limit_cli ip list\n"
              << "  roche_limit_cli ip add <ip-or-cidr> --allow|--deny [--note TEXT]\n"
              << "  roche_limit_cli ip set <rule-id> [--value <ip-or-cidr>] [--allow|--deny] [--note TEXT]\n"
              << "  roche_limit_cli ip set <rule-id> [--service <name|*>] [--level <0-90>] [--note TEXT]\n"
              << "  roche_limit_cli ip set <ip-or-cidr> [--service <name|*>] --level <0-90> [--note TEXT]\n"
              << "  roche_limit_cli ip remove <rule-id>\n"
              << "  roche_limit_cli key list\n"
              << "  roche_limit_cli key add <plain-api-key> [--service <name>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]\n"
              << "  roche_limit_cli key gen [--service <name>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]\n"
              << "  roche_limit_cli key set <api-key-id> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]\n"
              << "  roche_limit_cli key disable <api-key-id>\n"
              << "  roche_limit_cli key remove <api-key-id>\n"
              << "  roche_limit_cli user list\n"
              << "  roche_limit_cli user add <username> [--password <plain>] [--note TEXT]\n"
              << "  roche_limit_cli user set-password <user-id> [--password <plain>]\n"
              << "  roche_limit_cli user set <user-id> [--note TEXT] [--disable|--enable]\n"
              << "  roche_limit_cli user set <user-id> [--service <name|*>] [--level <0-99>] [--note TEXT]\n"
              << "  roche_limit_cli user session-list [--user-id <id>]\n"
              << "  roche_limit_cli user revoke-session <session-id>\n"
              << "  roche_limit_cli user revoke-all-sessions <user-id>\n"
              << "  roche_limit_cli user disable <user-id>\n"
              << "  roche_limit_cli user remove <user-id>\n";
    if (experimental_cli_enabled()) {
        std::cout << "\nExperimental:\n"
                  << "  roche_limit_cli ip compact-ids\n"
                  << "  roche_limit_cli key compact-ids\n"
                  << "  roche_limit_cli user compact-ids\n";
    }
}

}  // namespace roche_limit::cli
