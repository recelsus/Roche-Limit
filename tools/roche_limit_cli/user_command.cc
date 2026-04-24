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

    if (action == "session-list") {
        const auto options = parse_options(args, 3);
        const auto sessions = repository.list_user_sessions(
            optional_option(options, "--user-id").has_value()
                ? std::optional<std::int64_t>(
                      parse_int64(*optional_option(options, "--user-id"),
                                  "user id"))
                : std::nullopt);
        std::vector<std::vector<std::string>> rows;
        for (const auto& session : sessions) {
            rows.push_back({
                std::to_string(session.id),
                std::to_string(session.user_id),
                session.absolute_expires_at,
                session.idle_expires_at,
                session.last_seen_at,
                session.last_rotated_at,
                session.revoked_at.has_value() ? *session.revoked_at : "-",
            });
        }
        print_table({"id", "user_id", "absolute_expires_at", "idle_expires_at",
                     "last_seen_at", "last_rotated_at", "revoked_at"},
                    rows);
        return;
    }

    if (action == "compact-ids") {
        require_experimental_cli("user compact-ids");
        repository.compact_user_ids();
        std::cout << "compacted user ids\n";
        return;
    }

    if (action == "disable" || action == "remove" || action == "set-password" || action == "set") {
        if (args.size() < 4) {
            fail("missing user id");
        }
    }

    if (action == "revoke-session") {
        repository.revoke_user_session_by_id(parse_int64(args[3], "session id"));
        std::cout << "revoked session\n";
        return;
    }

    if (action == "revoke-all-sessions") {
        repository.revoke_all_user_sessions(parse_int64(args[3], "user id"));
        std::cout << "revoked all user sessions\n";
        return;
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
        const auto user_id = parse_int64(args[3], "user id");
        repository.upsert_user_credential(user_id,
                                          roche_limit::auth_core::hash_password(password));
        repository.revoke_all_user_sessions(user_id);
        std::cout << "updated user password\n";
        return;
    }

    if (action == "disable") {
        const auto user_id = parse_int64(args[3], "user id");
        repository.update_user(user_id, UpdateUserRecord{
            .enabled = false,
        });
        repository.revoke_all_user_sessions(user_id);
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
        repository.revoke_all_user_sessions(user_id);
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
    if (enable || disable) {
        repository.revoke_all_user_sessions(user_id);
    }
    std::cout << "updated user\n";
}

}  // namespace roche_limit::cli
