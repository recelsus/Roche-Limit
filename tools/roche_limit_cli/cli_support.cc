#include "cli_support.h"

#include <arpa/inet.h>
#include <cstdlib>

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
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

bool flag_option_enabled(const OptionsMap& options, std::string_view key) {
    const auto it = options.find(std::string(key));
    if (it == options.end()) {
        return false;
    }
    return it->second != "0" && it->second != "false" &&
           it->second != "FALSE" && it->second != "no" &&
           it->second != "off";
}

bool dry_run_requested(const OptionsMap& options) {
    return flag_option_enabled(options, "--dry-run");
}

void require_force_for_destructive_command(const OptionsMap& options,
                                           std::string_view command_name) {
    if (!flag_option_enabled(options, "--force")) {
        fail(std::string(command_name) +
             " is destructive; rerun with --dry-run to preview or --force to execute");
    }
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

bool is_help_argument(std::string_view value) {
    return value == "-h" || value == "--help" || value == "help";
}

bool is_known_command_domain(std::string_view domain) {
    return domain == "ip" || domain == "key" || domain == "cert" ||
           domain == "user" || domain == "audit";
}

bool is_known_command_action(std::string_view domain, std::string_view action) {
    if (domain == "ip") {
        return action == "list" || action == "add" || action == "set" ||
               action == "remove" || action == "compact-ids";
    }
    if (domain == "key") {
        return action == "list" || action == "add" || action == "gen" ||
               action == "rotate" || action == "set" || action == "disable" ||
               action == "disable-all" || action == "remove" ||
               action == "compact-ids";
    }
    if (domain == "cert") {
        return action == "list" || action == "add" || action == "set" ||
               action == "disable" || action == "enable" ||
               action == "remove";
    }
    if (domain == "user") {
        return action == "list" || action == "add" || action == "set" ||
               action == "set-password" || action == "session-list" ||
               action == "revoke-session" || action == "revoke-all-sessions" ||
               action == "revoke-all-user-sessions" || action == "disable" ||
               action == "remove" || action == "compact-ids";
    }
    if (domain == "audit") {
        return action == "list" || action == "show" || action == "cleanup";
    }
    return false;
}

bool command_action_requires_target(std::string_view domain,
                                    std::string_view action) {
    if (domain == "ip") {
        return action == "add" || action == "set" || action == "remove";
    }
    if (domain == "key") {
        return action == "add" || action == "rotate" || action == "set" ||
               action == "disable" || action == "remove";
    }
    if (domain == "cert") {
        return action == "add" || action == "set" || action == "disable" ||
               action == "enable" || action == "remove";
    }
    if (domain == "user") {
        return action == "add" || action == "set" || action == "set-password" ||
               action == "revoke-session" || action == "revoke-all-sessions" ||
               action == "disable" || action == "remove";
    }
    return domain == "audit" && action == "show";
}

std::string help_text(std::optional<std::string_view> domain,
                      std::optional<std::string_view> action) {
    std::ostringstream out;
    const auto usage = [&out](std::string_view text) {
        out << "Usage:\n  " << text << "\n";
    };

    if (!domain.has_value()) {
        out << "Roche-Limit management CLI\n\n";
        usage("roche_limit_cli <command> [options]");
        out << "\nCommands:\n"
            << "  ip      Manage IP allow/deny rules and service levels\n"
            << "  key     Manage API keys, scopes, rotation, and emergency disable\n"
            << "  cert    Manage client certificates and service levels\n"
            << "  user    Manage users, service levels, and sessions\n"
            << "  audit   Inspect audit events and manage retention\n"
            << "\nHelp:\n"
            << "  roche_limit_cli <command> -h\n"
            << "  roche_limit_cli <command> <action> -h\n"
            << "  roche_limit_cli help <command> [action]\n"
            << "\nGlobal options:\n"
            << "  --verbose  Enable verbose diagnostic logging\n";
        return out.str();
    }

    const std::string topic(*domain);
    const std::string operation = action.has_value() ? std::string(*action) : "";

    if (topic == "ip") {
        if (!operation.empty()) {
            if (operation == "list") {
                usage("roche_limit_cli ip list");
                out << "\nLists shared IP rules and service-specific overrides.\n";
            } else if (operation == "add") {
                usage("roche_limit_cli ip add <ip-or-cidr> --allow|--deny [--note TEXT]");
                out << "\nAdds a shared IPv4/IPv6 single-address or CIDR rule.\n";
            } else if (operation == "set") {
                usage("roche_limit_cli ip set <rule-id|ip-or-cidr> [options]");
                out << "\nOptions:\n"
                    << "  --value <ip-or-cidr>   Replace a shared rule value\n"
                    << "  --allow | --deny      Replace a shared rule effect\n"
                    << "  --service <name|*>    Select a service override\n"
                    << "  --level <0-99>        Set the service access level\n"
                    << "  --note TEXT           Set a note\n";
            } else if (operation == "remove") {
                usage("roche_limit_cli ip remove <rule-id>");
                out << "\nDeletes the shared rule and its service-level overrides.\n";
            } else {
                out << "Unknown ip action: " << operation << "\n\n";
            }
        }
        if (operation.empty() || out.str().starts_with("Unknown")) {
            out << "Manage IP allow/deny rules and service-specific access levels.\n\n";
            usage("roche_limit_cli ip <action> [options]");
            out << "\nActions:\n"
                << "  list       List shared rules and service overrides\n"
                << "  add        Add a shared allow/deny rule\n"
                << "  set        Update a shared rule or service override\n"
                << "  remove     Delete a shared rule and dependent overrides\n"
                << "\nRun `roche_limit_cli ip <action> -h` for action help.\n";
        }
        return out.str();
    }

    if (topic == "key") {
        if (!operation.empty()) {
            if (operation == "list") {
                usage("roche_limit_cli key list");
                out << "\nLists key prefixes, scopes, levels, status, expiry, and usage stats.\n";
            } else if (operation == "add") {
                usage("roche_limit_cli key add <plain-api-key> [--service <name|*>] [--level <0-99>] [--expires-at <timestamp>] [--note TEXT]");
                out << "\nStores a supplied key. Plain key material is not stored.\n";
            } else if (operation == "gen") {
                usage("roche_limit_cli key gen [--service <name|*>] [--level <0-99>] [--expires-at <timestamp>] [--note TEXT]");
                out << "\nGenerates a key and displays the plain value once.\n";
            } else if (operation == "rotate") {
                usage("roche_limit_cli key rotate <api-key-id> [options] [--dry-run|--force]");
                out << "\nCreates a replacement and disables the old key.\n"
                    << "Use --dry-run to preview. --force is required to execute.\n";
            } else if (operation == "set") {
                usage("roche_limit_cli key set <api-key-id> [--service <name|*>] [--level <0-99>] [--expires-at <timestamp>] [--note TEXT]");
                out << "\nUpdates key scope, level, expiry, or note.\n";
            } else if (operation == "disable") {
                usage("roche_limit_cli key disable <api-key-id> [--dry-run|--force]");
                out << "\nDisables one key. Use --dry-run first; --force executes.\n";
            } else if (operation == "disable-all") {
                usage("roche_limit_cli key disable-all [--dry-run|--force]");
                out << "\nEmergency operation that disables every enabled key.\n"
                    << "Use --dry-run first; --force executes.\n";
            } else if (operation == "remove") {
                usage("roche_limit_cli key remove <api-key-id> [--dry-run|--force]");
                out << "\nPermanently deletes one key. Use --dry-run first; --force executes.\n";
            } else {
                out << "Unknown key action: " << operation << "\n\n";
            }
        }
        if (operation.empty() || out.str().starts_with("Unknown")) {
            out << "Manage API keys and service scopes.\n\n";
            usage("roche_limit_cli key <action> [options]");
            out << "\nRead actions:\n"
                << "  list          List keys without exposing plain values\n"
                << "\nCreate/update actions:\n"
                << "  add           Store a supplied API key\n"
                << "  gen           Generate and display a new API key once\n"
                << "  set           Update scope, level, expiry, or note\n"
                << "\nHigh-impact actions:\n"
                << "  rotate        Replace a key and disable the old key\n"
                << "  disable       Disable one key\n"
                << "  disable-all   Emergency-disable every enabled key\n"
                << "  remove        Permanently delete one key\n"
                << "\nHigh-impact actions support --dry-run and require --force to execute.\n"
                << "Run `roche_limit_cli key <action> -h` for action help.\n";
        }
        return out.str();
    }

    if (topic == "cert") {
        if (!operation.empty()) {
            if (operation == "list") {
                usage("roche_limit_cli cert list");
                out << "\nLists client certificates and service-specific levels.\n";
            } else if (operation == "add") {
                usage("roche_limit_cli cert add <fingerprint> [--service <name|*>] [--level <0-99>] [--serial TEXT] [--subject TEXT] [--issuer TEXT] [--not-before <timestamp>] [--not-after <timestamp>] [--note TEXT]");
                out << "\nAdds a client certificate and initial service level.\n";
            } else if (operation == "set") {
                usage("roche_limit_cli cert set <cert-id> [--service <name|*>] --level <0-99> [--note TEXT]");
                out << "\nUpserts a service-specific level for a certificate.\n";
            } else if (operation == "disable") {
                usage("roche_limit_cli cert disable <cert-id> [--dry-run|--force]");
                out << "\nDisables one certificate. Use --dry-run first; --force executes.\n";
            } else if (operation == "enable") {
                usage("roche_limit_cli cert enable <cert-id> [--dry-run|--force]");
                out << "\nEnables one certificate. Use --dry-run first; --force executes.\n";
            } else if (operation == "remove") {
                usage("roche_limit_cli cert remove <cert-id> [--dry-run|--force]");
                out << "\nPermanently deletes one certificate and service levels.\n";
            } else {
                out << "Unknown cert action: " << operation << "\n\n";
            }
        }
        if (operation.empty() || out.str().starts_with("Unknown")) {
            out << "Manage client certificates and service levels.\n\n";
            usage("roche_limit_cli cert <action> [options]");
            out << "\nRead actions:\n"
                << "  list       List certificates and service levels\n"
                << "\nCreate/update actions:\n"
                << "  add        Add a certificate and initial service level\n"
                << "  set        Upsert a service-specific level\n"
                << "\nHigh-impact actions:\n"
                << "  disable    Disable one certificate\n"
                << "  enable     Enable one certificate\n"
                << "  remove     Permanently delete one certificate\n"
                << "\nHigh-impact actions support --dry-run and require --force to execute.\n"
                << "Run `roche_limit_cli cert <action> -h` for action help.\n";
        }
        return out.str();
    }

    if (topic == "user") {
        if (!operation.empty()) {
            if (operation == "list") {
                usage("roche_limit_cli user list");
                out << "\nLists users and service-specific access levels.\n";
            } else if (operation == "add") {
                usage("roche_limit_cli user add <username> [--password <plain>] [--note TEXT]");
                out << "\nCreates a user and password credential.\n";
            } else if (operation == "set") {
                usage("roche_limit_cli user set <user-id> [options] [--dry-run|--force]");
                out << "\nUpdates note, enabled state, or a service level.\n"
                    << "Changes that revoke sessions support --dry-run and require --force.\n";
            } else if (operation == "set-password") {
                usage("roche_limit_cli user set-password <user-id> [--password <plain>] [--dry-run|--force]");
                out << "\nChanges the password and revokes the user's sessions. --force is required.\n";
            } else if (operation == "session-list") {
                usage("roche_limit_cli user session-list [--user-id <id>]");
                out << "\nLists sessions, optionally filtered by user.\n";
            } else if (operation == "revoke-session") {
                usage("roche_limit_cli user revoke-session <session-id> [--dry-run|--force]");
                out << "\nRevokes one session. --force is required.\n";
            } else if (operation == "revoke-all-sessions") {
                usage("roche_limit_cli user revoke-all-sessions <user-id> [--dry-run|--force]");
                out << "\nRevokes every session belonging to one user. --force is required.\n";
            } else if (operation == "revoke-all-user-sessions") {
                usage("roche_limit_cli user revoke-all-user-sessions [--dry-run|--force]");
                out << "\nEmergency operation that revokes every active user session. --force is required.\n";
            } else if (operation == "disable") {
                usage("roche_limit_cli user disable <user-id> [--dry-run|--force]");
                out << "\nDisables a user and revokes their sessions. --force is required.\n";
            } else if (operation == "remove") {
                usage("roche_limit_cli user remove <user-id> [--dry-run|--force]");
                out << "\nDeletes a user and dependent records. --force is required.\n";
            } else {
                out << "Unknown user action: " << operation << "\n\n";
            }
        }
        if (operation.empty() || out.str().starts_with("Unknown")) {
            out << "Manage users, service access levels, and sessions.\n\n";
            usage("roche_limit_cli user <action> [options]");
            out << "\nUser actions:\n"
                << "  list                      List users and service levels\n"
                << "  add                       Create a user\n"
                << "  set                       Update user state or service level\n"
                << "  set-password              Change password and revoke sessions\n"
                << "  disable                   Disable a user and revoke sessions\n"
                << "  remove                    Delete a user and dependent records\n"
                << "\nSession actions:\n"
                << "  session-list              List sessions\n"
                << "  revoke-session            Revoke one session\n"
                << "  revoke-all-sessions       Revoke one user's sessions\n"
                << "  revoke-all-user-sessions  Emergency-revoke all sessions\n"
                << "\nHigh-impact actions support --dry-run and require --force to execute.\n"
                << "Run `roche_limit_cli user <action> -h` for action help.\n";
        }
        return out.str();
    }

    if (topic == "audit") {
        if (!operation.empty()) {
            if (operation == "list") {
                usage("roche_limit_cli audit list [filters]");
                out << "\nFilters:\n"
                    << "  --limit <1-500>       Maximum rows, default 50\n"
                    << "  --event-type <type>   Match event_type\n"
                    << "  --result <result>     Match result\n"
                    << "  --service <name>      Match service_name\n"
                    << "  --request-id <id>     Match request_id\n"
                    << "  --actor-type <type>   Match actor_type\n"
                    << "  --reason <reason>     Match reason\n"
                    << "  --client-ip <ip>      Match client_ip\n";
            } else if (operation == "show") {
                usage("roche_limit_cli audit show <event-id>");
                out << "\nShows all stored fields, metadata, and hash-chain values.\n";
            } else if (operation == "cleanup") {
                usage("roche_limit_cli audit cleanup [--retention-days <days>] [--max-rows <count>]");
                out << "\nApplies retention and row-cap limits and records an audit_cleanup event.\n";
            } else {
                out << "Unknown audit action: " << operation << "\n\n";
            }
        }
        if (operation.empty() || out.str().starts_with("Unknown")) {
            out << "Inspect audit events and manage retention.\n\n";
            usage("roche_limit_cli audit <action> [options]");
            out << "\nRead actions:\n"
                << "  list       List recent events with optional exact-match filters\n"
                << "  show       Show every stored field for one event\n"
                << "\nRetention actions:\n"
                << "  cleanup    Apply retention and row-cap limits\n"
                << "\nRead actions do not create audit events.\n"
                << "Run `roche_limit_cli audit <action> -h` for action help.\n";
        }
        return out.str();
    }

    out << "Unknown help topic: " << topic << "\n\n" << help_text();
    return out.str();
}

void print_help(std::optional<std::string_view> domain,
                std::optional<std::string_view> action) {
    std::cout << help_text(domain, action);
}

void print_usage() {
    print_help();
}

}  // namespace roche_limit::cli
