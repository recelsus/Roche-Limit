#include "key_command.h"

#include "auth_core/api_key_hasher.h"
#include "cli_support.h"

#include <iostream>

namespace roche_limit::cli {

using roche_limit::auth_store::NewApiKeyRecord;
using roche_limit::auth_store::RuleRepository;
using roche_limit::auth_store::UpdateApiKeyRecord;

namespace {

std::string api_key_prefix(std::string_view plain_api_key) {
    constexpr std::size_t kPrefixLength = 8;
    return std::string(plain_api_key.substr(0, std::min(kPrefixLength, plain_api_key.size())));
}

}  // namespace

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
                record.key_prefix.has_value() ? *record.key_prefix : "-",
                record.key_hash,
                printable_service_name(record.service_name),
                std::to_string(record.access_level),
                bool_label(record.enabled),
                record.note.has_value() ? *record.note : "-",
            });
        }
        print_table({"id", "prefix", "hash", "service", "level", "status", "note"}, rows);
        return;
    }

    if (action == "compact-ids") {
        require_experimental_cli("key compact-ids");
        repository.compact_api_key_ids();
        std::cout << "compacted api key ids\n";
        return;
    }

    if (action == "disable" || action == "remove") {
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
    }

    const auto options = parse_options(args, action == "gen" ? 3 : 4);
    if (action == "add") {
        if (args.size() < 4) {
            fail("missing plain api key");
        }
        const auto plain_api_key = args[3];
        const auto level_option = optional_option(options, "--level");
        const auto api_key_id = repository.insert_api_key(NewApiKeyRecord{
            .key_hash = roche_limit::auth_core::hash_api_key(plain_api_key),
            .key_prefix = api_key_prefix(plain_api_key),
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
            .key_hash = roche_limit::auth_core::hash_api_key(plain_api_key),
            .key_prefix = api_key_prefix(plain_api_key),
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

}  // namespace roche_limit::cli
