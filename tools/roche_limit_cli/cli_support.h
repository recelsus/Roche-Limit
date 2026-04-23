#pragma once

#include "auth_core/ip_rule_record.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace roche_limit::cli {

using OptionsMap = std::unordered_map<std::string, std::string>;

struct ParsedCliIp {
    roche_limit::auth_core::AddressFamily family;
    roche_limit::auth_core::IpRuleType rule_type;
    std::optional<int> prefix_length;
};

[[noreturn]] void fail(std::string_view message);

OptionsMap parse_options(const std::vector<std::string>& args, std::size_t start_index);
std::string require_option(const OptionsMap& options, std::string_view key);
std::optional<std::string> optional_option(const OptionsMap& options, std::string_view key);

std::int64_t parse_int64(std::string_view value, std::string_view name);
int parse_int(std::string_view value, std::string_view name);

std::string to_string(roche_limit::auth_core::AddressFamily value);
std::string to_string(roche_limit::auth_core::IpRuleType value);
std::string to_string(roche_limit::auth_core::IpRuleEffect value);
std::string printable_service_name(const std::optional<std::string>& value);
std::string printable_service_name(std::string_view value);
std::string bool_label(bool value);
bool experimental_cli_enabled();
void require_experimental_cli(std::string_view command_name);

bool looks_like_ip_or_cidr(std::string_view value);
std::optional<std::string> parse_service_name_option(const OptionsMap& options,
                                                     std::string_view key);

void print_table(const std::vector<std::string>& header,
                 const std::vector<std::vector<std::string>>& rows);

ParsedCliIp parse_cli_ip(std::string_view value);

std::string generate_api_key();
std::string prompt_password();
std::string option_or_prompt_password(const OptionsMap& options);

void print_usage();

}  // namespace roche_limit::cli
