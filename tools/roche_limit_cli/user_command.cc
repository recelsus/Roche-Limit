#include "user_command.h"

#include "auth_core/password_hasher.h"
#include "cli_support.h"

#include <iostream>

namespace roche_limit::cli {

using roche_limit::auth_store::NewUserRecord;
using roche_limit::auth_store::NewUserServiceLevel;
using roche_limit::auth_store::UpdateUserRecord;
using roche_limit::auth_store::UserRepository;

void handle_user_command(const UserRepository& repository, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        fail("missing user subcommand");
    }

    const auto& action = args[2];
    if (action == "list") {
        const auto users = repository.list_users();
        std::vector<std::vector<std::string>> user_rows;
        for (const auto& user : users) {
            user_rows.push_back({
                std::to_string(user.id),
                user.username,
                bool_label(user.enabled),
                user.note.has_value() ? *user.note : "-",
            });
        }
        print_table({"id", "username", "status", "note"}, user_rows);

        const auto service_levels = repository.list_user_service_levels();
        if (!service_levels.empty()) {
            std::cout << '\n';
            std::vector<std::vector<std::string>> level_rows;
            for (const auto& record : service_levels) {
                level_rows.push_back({
                    std::to_string(record.id),
                    std::to_string(record.user_id),
                    printable_service_name(std::string_view(record.service_name)),
                    std::to_string(record.access_level),
                    bool_label(record.enabled),
                    record.note.has_value() ? *record.note : "-",
                });
            }
            print_table({"id", "user_id", "service", "level", "status", "note"}, level_rows);
        }
        return;
    }

    if (action == "compact-ids") {
        repository.compact_user_ids();
        std::cout << "compacted user ids\n";
        return;
    }

    if (action == "disable" || action == "remove" || action == "set-password" || action == "set") {
        if (args.size() < 4) {
            fail("missing user id");
        }
    }

    if (action == "add") {
        if (args.size() < 4) {
            fail("missing username");
        }
        const auto options = parse_options(args, 4);
        const auto user_id = repository.insert_user(NewUserRecord{
            .username = args[3],
            .note = optional_option(options, "--note"),
        });
        const auto password = option_or_prompt_password(options);
        repository.upsert_user_credential(user_id, roche_limit::auth_core::hash_password(password));
        std::cout << "created user id=" << user_id << '\n';
        return;
    }

    if (action == "set-password") {
        const auto options = parse_options(args, 4);
        const auto password = option_or_prompt_password(options);
        repository.upsert_user_credential(parse_int64(args[3], "user id"),
                                          roche_limit::auth_core::hash_password(password));
        std::cout << "updated user password\n";
        return;
    }

    if (action == "disable") {
        repository.update_user(parse_int64(args[3], "user id"), UpdateUserRecord{
            .enabled = false,
        });
        std::cout << "disabled user\n";
        return;
    }

    if (action == "remove") {
        repository.delete_user(parse_int64(args[3], "user id"));
        std::cout << "deleted user\n";
        return;
    }

    if (action != "set") {
        fail("unknown user subcommand");
    }

    const auto options = parse_options(args, 4);
    const auto user_id = parse_int64(args[3], "user id");
    const bool updates_service_level = options.contains("--level") || options.contains("--service");
    if (updates_service_level) {
        const auto level_option = optional_option(options, "--level");
        if (!level_option.has_value()) {
            fail("user service level update requires --level");
        }
        const auto record_id = repository.upsert_user_service_level(NewUserServiceLevel{
            .user_id = user_id,
            .service_name = optional_option(options, "--service").value_or("*"),
            .access_level = parse_int(*level_option, "--level"),
            .note = optional_option(options, "--note"),
        });
        std::cout << "upserted user service level id=" << record_id << '\n';
        return;
    }

    const bool enable = options.contains("--enable");
    const bool disable = options.contains("--disable");
    if (enable && disable) {
        fail("user set accepts only one of --enable or --disable");
    }

    repository.update_user(user_id, UpdateUserRecord{
        .note_is_set = options.contains("--note"),
        .note = optional_option(options, "--note"),
        .enabled = enable ? std::optional<bool>(true)
                          : (disable ? std::optional<bool>(false) : std::optional<bool>{}),
    });
    std::cout << "updated user\n";
}

}  // namespace roche_limit::cli
