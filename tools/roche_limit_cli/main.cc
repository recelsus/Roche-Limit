#include "auth_core/api_key_hasher.h"
#include "auth_core/ip_rule_record.h"
#include "auth_store/rule_repository.h"
#include "auth_store/schema_bootstrap.h"

#include <arpa/inet.h>
#include <cstdlib>

#include <array>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace {

using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::ApiKeyRecord;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleRecord;
using roche_limit::auth_core::IpRuleType;
using roche_limit::auth_core::IpServiceLevelRecord;
using roche_limit::auth_store::NewApiKeyRecord;
using roche_limit::auth_store::NewIpRule;
using roche_limit::auth_store::NewIpServiceLevel;
using roche_limit::auth_store::RuleRepository;
using roche_limit::auth_store::UpdateApiKeyRecord;
using roche_limit::auth_store::UpdateIpRule;

constexpr bool kShowPlainApiKeys = true;

[[noreturn]] void fail(std::string_view message) {
    throw std::runtime_error(std::string(message));
}

std::unordered_map<std::string, std::string> parse_options(const std::vector<std::string>& args,
                                                           std::size_t start_index) {
    std::unordered_map<std::string, std::string> options;

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

std::string require_option(const std::unordered_map<std::string, std::string>& options,
                           std::string_view key) {
    const auto it = options.find(std::string(key));
    if (it == options.end()) {
        fail(std::string("missing required option: ") + std::string(key));
    }
    return it->second;
}

std::optional<std::string> optional_option(
    const std::unordered_map<std::string, std::string>& options,
    std::string_view key) {
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

AddressFamily parse_address_family(std::string_view value) {
    if (value == "ipv4") {
        return AddressFamily::IPv4;
    }
    if (value == "ipv6") {
        return AddressFamily::IPv6;
    }
    fail("address family must be ipv4 or ipv6");
}

IpRuleType parse_rule_type(std::string_view value) {
    if (value == "single") {
        return IpRuleType::Single;
    }
    if (value == "cidr") {
        return IpRuleType::Cidr;
    }
    fail("rule type must be single or cidr");
}

IpRuleEffect parse_effect(std::string_view value) {
    if (value == "allow") {
        return IpRuleEffect::Allow;
    }
    if (value == "deny") {
        return IpRuleEffect::Deny;
    }
    fail("effect must be allow or deny");
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

bool looks_like_ip_or_cidr(std::string_view value) {
    return value.find('/') != std::string_view::npos || value.find('.') != std::string_view::npos ||
           value.find(':') != std::string_view::npos;
}

std::optional<std::string> parse_service_name_option(
    const std::unordered_map<std::string, std::string>& options,
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

struct ParsedCliIp {
    AddressFamily family;
    IpRuleType rule_type;
    std::optional<int> prefix_length;
};

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

void print_usage() {
    std::cout << "Usage:\n"
              << "  roche_limit_cli ip list\n"
              << "  roche_limit_cli ip add <ip-or-cidr> --allow|--deny [--note TEXT]\n"
              << "  roche_limit_cli ip set <rule-id> [--value <ip-or-cidr>] [--allow|--deny] [--note TEXT]\n"
              << "  roche_limit_cli ip set <ip-or-cidr> [--service <name|*>] --level <0-90> [--note TEXT]\n"
              << "  roche_limit_cli ip remove <rule-id>\n"
              << "  roche_limit_cli key list\n"
              << "  roche_limit_cli key add <plain-api-key> [--service <name>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]\n"
              << "  roche_limit_cli key gen [--service <name>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]\n"
              << "  roche_limit_cli key set <api-key-id> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]\n"
              << "  roche_limit_cli key clear-plain <api-key-id>\n"
              << "  roche_limit_cli key disable <api-key-id>\n"
              << "  roche_limit_cli key remove <api-key-id>\n";
}

void handle_ip_command(const RuleRepository& repository, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        fail("missing ip subcommand");
    }

    const auto& action = args[2];
    if (action == "list") {
        std::vector<std::vector<std::string>> rows;
        for (const auto effect : {IpRuleEffect::Deny, IpRuleEffect::Allow}) {
            const auto rules = repository.list_ip_rules(effect);
            for (const auto& rule : rules) {
                rows.push_back({
                    std::to_string(rule.id),
                    to_string(rule.effect),
                    rule.value_text,
                    to_string(rule.address_family),
                    to_string(rule.rule_type),
                    rule.prefix_length.has_value() ? std::to_string(*rule.prefix_length) : "-",
                    bool_label(rule.enabled),
                });
            }
        }
        print_table({"id", "effect", "value", "family", "type", "prefix", "status"}, rows);

        const auto service_levels = repository.list_ip_service_levels();
        if (!service_levels.empty()) {
            std::cout << '\n';
            std::vector<std::vector<std::string>> level_rows;
            for (const auto& record : service_levels) {
                level_rows.push_back({
                    std::to_string(record.id),
                    std::to_string(record.ip_rule_id),
                    printable_service_name(std::string_view(record.service_name)),
                    std::to_string(record.access_level),
                    bool_label(record.enabled),
                    record.note.has_value() ? *record.note : "-",
                });
            }
            print_table({"id", "ip_rule_id", "service", "level", "status", "note"}, level_rows);
        }
        return;
    }

    if (action == "remove") {
        if (args.size() < 4) {
            fail("missing ip rule id");
        }
        repository.delete_ip_rule(parse_int64(args[3], "ip rule id"));
        std::cout << "deleted ip rule\n";
        return;
    }

    if (args.size() < 4) {
        fail("missing ip value");
    }

    const auto target = args[3];
    const auto options = parse_options(args, 4);
    if (action == "add") {
        const auto parsed_ip = parse_cli_ip(target);
        const bool allow = options.contains("--allow");
        const bool deny = options.contains("--deny");
        if (allow == deny) {
            fail("ip add requires exactly one of --allow or --deny");
        }

        const auto rule_id = repository.insert_ip_rule(NewIpRule{
            .value_text = target,
            .address_family = parsed_ip.family,
            .rule_type = parsed_ip.rule_type,
            .prefix_length = parsed_ip.prefix_length,
            .effect = allow ? IpRuleEffect::Allow : IpRuleEffect::Deny,
            .note = optional_option(options, "--note"),
        });
        std::cout << "created ip rule id=" << rule_id << '\n';
        return;
    }

    if (action == "set") {
        if (looks_like_ip_or_cidr(target)) {
            const auto matched_rule = repository.find_allow_ip_rule_by_value(target);
            if (!matched_rule.has_value()) {
                fail("ip set requires an existing allow ip rule");
            }

            const auto record_id = repository.upsert_ip_service_level(NewIpServiceLevel{
                .ip_rule_id = matched_rule->id,
                .service_name = optional_option(options, "--service").value_or("*"),
                .access_level = parse_int(require_option(options, "--level"), "--level"),
                .note = optional_option(options, "--note"),
            });
            std::cout << "upserted ip service level id=" << record_id << '\n';
            return;
        }

        const bool allow = options.contains("--allow");
        const bool deny = options.contains("--deny");
        if (allow && deny) {
            fail("ip set accepts only one of --allow or --deny");
        }

        UpdateIpRule update_ip_rule{
            .note_is_set = options.contains("--note"),
            .note = optional_option(options, "--note"),
        };
        if (const auto value = optional_option(options, "--value"); value.has_value()) {
            const auto parsed_ip = parse_cli_ip(*value);
            update_ip_rule.value_text = *value;
            update_ip_rule.address_family = parsed_ip.family;
            update_ip_rule.rule_type = parsed_ip.rule_type;
            update_ip_rule.prefix_length = parsed_ip.prefix_length;
        }
        if (allow || deny) {
            update_ip_rule.effect = allow ? IpRuleEffect::Allow : IpRuleEffect::Deny;
        }
        repository.update_ip_rule(parse_int64(target, "ip rule id"), update_ip_rule);
        std::cout << "updated ip rule\n";
        return;
    }

    fail("unknown ip subcommand");
}

void handle_key_command(const RuleRepository& repository, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        fail("missing key subcommand");
    }

    const auto& action = args[2];
    if (action == "list") {
        const auto records = repository.list_api_keys();
        std::vector<std::vector<std::string>> rows;
        for (const auto& record : records) {
            rows.push_back({
                std::to_string(record.id),
                kShowPlainApiKeys ? (record.key_plain.has_value() ? *record.key_plain : "-")
                                  : "[hidden]",
                record.key_hash,
                printable_service_name(record.service_name),
                std::to_string(record.access_level),
                bool_label(record.enabled),
                record.note.has_value() ? *record.note : "-",
            });
        }
        print_table({"id", "plain", "hash", "service", "level", "status", "note"}, rows);
        return;
    }

    if (action == "disable" || action == "remove" || action == "clear-plain") {
        if (args.size() < 4) {
            fail("missing api key id");
        }

        const auto api_key_id = parse_int64(args[3], "api key id");
        if (action == "disable") {
            repository.disable_api_key(api_key_id);
            std::cout << "disabled api key\n";
            return;
        }
        if (action == "remove") {
            repository.delete_api_key(api_key_id);
            std::cout << "deleted api key\n";
            return;
        }
        repository.clear_api_key_plain(api_key_id);
        std::cout << "cleared api key plaintext\n";
        return;
    }

    const auto options = parse_options(args, action == "gen" ? 3 : 4);
    if (action == "add") {
        if (args.size() < 4) {
            fail("missing plain api key");
        }
        const auto plain_api_key = args[3];
        const auto level_option = optional_option(options, "--level");
        const auto api_key_id = repository.insert_api_key(NewApiKeyRecord{
            .key_plain = plain_api_key,
            .key_hash = roche_limit::auth_core::hash_api_key(plain_api_key),
            .key_prefix = std::nullopt,
            .service_name = parse_service_name_option(options, "--service"),
            .access_level = level_option.has_value() ? parse_int(*level_option, "--level") : 30,
            .expires_at = optional_option(options, "--expires-at"),
            .note = optional_option(options, "--note"),
        });
        std::cout << "created api key id=" << api_key_id << '\n';
        return;
    }

    if (action == "gen") {
        const auto plain_api_key = generate_api_key();
        const auto level_option = optional_option(options, "--level");
        const auto api_key_id = repository.insert_api_key(NewApiKeyRecord{
            .key_plain = plain_api_key,
            .key_hash = roche_limit::auth_core::hash_api_key(plain_api_key),
            .key_prefix = std::nullopt,
            .service_name = parse_service_name_option(options, "--service"),
            .access_level = level_option.has_value() ? parse_int(*level_option, "--level") : 30,
            .expires_at = optional_option(options, "--expires-at"),
            .note = optional_option(options, "--note"),
        });
        std::cout << "created api key id=" << api_key_id << '\n';
        std::cout << "plain=" << plain_api_key << '\n';
        return;
    }

    if (action == "set") {
        if (args.size() < 4) {
            fail("missing api key id");
        }
        UpdateApiKeyRecord update_api_key_record{
            .service_name_is_set = options.contains("--service"),
            .service_name = parse_service_name_option(options, "--service"),
            .expires_at_is_set = options.contains("--expires-at"),
            .expires_at = optional_option(options, "--expires-at"),
            .note_is_set = options.contains("--note"),
            .note = optional_option(options, "--note"),
        };
        if (const auto level = optional_option(options, "--level"); level.has_value()) {
            update_api_key_record.access_level = parse_int(*level, "--level");
        }
        repository.update_api_key(parse_int64(args[3], "api key id"), update_api_key_record);
        std::cout << "updated api key\n";
        return;
    }

    fail("unknown key subcommand");
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const std::vector<std::string> args(argv, argv + argc);
        if (args.size() < 2) {
            print_usage();
            return 1;
        }

        const auto executable_path = argc > 0 ? std::filesystem::path(argv[0]) : std::filesystem::path{};
        const auto bootstrap_result = roche_limit::auth_store::bootstrap_sqlite_schema(executable_path);
        RuleRepository repository(bootstrap_result.database_path);

        const auto& domain = args[1];
        if (domain == "ip") {
            handle_ip_command(repository, args);
            return 0;
        }
        if (domain == "key") {
            handle_key_command(repository, args);
            return 0;
        }

        print_usage();
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "roche-limit-cli: " << ex.what() << std::endl;
        return 1;
    }
}
