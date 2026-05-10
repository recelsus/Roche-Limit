#include "user_command.h"

#include "audit_logging.h"
#include "auth_core/password_hasher.h"
#include "cli_support.h"

#include <iostream>

namespace roche_limit::cli {

using roche_limit::auth_store::NewUserRecord;
using roche_limit::auth_store::NewUserServiceLevel;
using roche_limit::auth_store::UpdateUserRecord;
using roche_limit::auth_store::UserRepository;

namespace {

std::optional<roche_limit::auth_core::UserRecord>
find_user_by_id(const UserRepository& repository, std::int64_t user_id) {
    const auto users = repository.list_users();
    for (const auto& user : users) {
        if (user.id == user_id) {
            return user;
        }
    }
    return std::nullopt;
}

std::optional<roche_limit::auth_core::UserSessionRecord>
find_session_by_id(const UserRepository& repository, std::int64_t session_id) {
    const auto sessions = repository.list_user_sessions(std::nullopt);
    for (const auto& session : sessions) {
        if (session.id == session_id) {
            return session;
        }
    }
    return std::nullopt;
}

int active_session_count(const UserRepository& repository,
                         std::int64_t user_id) {
    int count = 0;
    for (const auto& session : repository.list_user_sessions(user_id)) {
        if (!session.revoked_at.has_value()) {
            ++count;
        }
    }
    return count;
}

void print_user_target(std::string_view operation,
                       const roche_limit::auth_core::UserRecord& user,
                       int active_sessions) {
    std::cout << operation << " user target\n";
    print_table({"id", "username", "status", "active_sessions", "note"},
                {{
                    std::to_string(user.id),
                    user.username,
                    bool_label(user.enabled),
                    std::to_string(active_sessions),
                    user.note.has_value() ? *user.note : "-",
                }});
}

void print_session_target(
    std::string_view operation,
    const roche_limit::auth_core::UserSessionRecord& session) {
    std::cout << operation << " session target\n";
    print_table({"id", "user_id", "absolute_expires_at", "idle_expires_at",
                 "last_seen_at", "revoked_at"},
                {{
                    std::to_string(session.id),
                    std::to_string(session.user_id),
                    session.absolute_expires_at,
                    session.idle_expires_at,
                    session.last_seen_at,
                    session.revoked_at.has_value() ? *session.revoked_at : "-",
                }});
}

std::string user_operation_details_json(std::int64_t user_id,
                                        int active_sessions,
                                        bool dry_run,
                                        bool force) {
    return std::string("{\"user_id\":") + std::to_string(user_id) +
           ",\"active_sessions\":" + std::to_string(active_sessions) +
           ",\"dry_run\":" + (dry_run ? "true" : "false") +
           ",\"force\":" + (force ? "true" : "false") + "}";
}

std::string session_operation_details_json(std::int64_t session_id,
                                           std::int64_t user_id,
                                           bool dry_run,
                                           bool force) {
    return std::string("{\"session_id\":") + std::to_string(session_id) +
           ",\"user_id\":" + std::to_string(user_id) +
           ",\"dry_run\":" + (dry_run ? "true" : "false") +
           ",\"force\":" + (force ? "true" : "false") + "}";
}

std::string session_bulk_operation_details_json(int active_sessions,
                                                bool dry_run,
                                                bool force) {
    return std::string("{\"active_sessions\":") +
           std::to_string(active_sessions) + ",\"dry_run\":" +
           (dry_run ? "true" : "false") + ",\"force\":" +
           (force ? "true" : "false") + "}";
}

}  // namespace

void handle_user_command(
    const UserRepository& repository,
    const roche_limit::auth_store::AuditRepository& audit_repository,
    const std::vector<std::string>& args) {
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

    if (action == "revoke-all-user-sessions") {
        const auto options = parse_options(args, 3);
        const auto sessions = repository.list_user_sessions(std::nullopt);
        std::vector<roche_limit::auth_core::UserSessionRecord> targets;
        for (const auto& session : sessions) {
            if (!session.revoked_at.has_value()) {
                targets.push_back(session);
            }
        }
        std::vector<std::vector<std::string>> rows;
        for (const auto& session : targets) {
            rows.push_back({
                std::to_string(session.id),
                std::to_string(session.user_id),
                session.absolute_expires_at,
                session.idle_expires_at,
                session.last_seen_at,
            });
        }
        std::cout << "revoke-all-user-sessions targets count="
                  << targets.size() << '\n';
        print_table({"id", "user_id", "absolute_expires_at",
                     "idle_expires_at", "last_seen_at"},
                    rows);
        if (dry_run_requested(options)) {
            audit_cli_success(
                audit_repository,
                "cli_user_revoke_all_user_sessions_dry_run", "session",
                std::nullopt, args,
                session_bulk_operation_details_json(
                    static_cast<int>(targets.size()), true,
                    flag_option_enabled(options, "--force")));
            std::cout << "dry-run: no sessions revoked\n";
            return;
        }
        require_force_for_destructive_command(
            options, "user revoke-all-user-sessions");
        for (const auto& session : targets) {
            repository.revoke_user_session_by_id(session.id);
        }
        audit_cli_success(
            audit_repository, "cli_user_revoke_all_user_sessions", "session",
            std::nullopt, args,
            session_bulk_operation_details_json(
                static_cast<int>(targets.size()), false, true));
        std::cout << "revoked all user sessions count=" << targets.size()
                  << '\n';
        return;
    }

    if (action == "compact-ids") {
        require_experimental_cli("user compact-ids");
        repository.compact_user_ids();
        audit_cli_success(audit_repository, "cli_user_compact_ids", "user",
                          std::nullopt, args);
        std::cout << "compacted user ids\n";
        return;
    }

    if (action == "disable" || action == "remove" ||
        action == "set-password" || action == "set" ||
        action == "revoke-session" || action == "revoke-all-sessions") {
        if (args.size() < 4) {
            fail(action == "revoke-session" ? "missing session id"
                                            : "missing user id");
        }
    }

    if (action == "revoke-session") {
        const auto session_id = parse_int64(args[3], "session id");
        const auto options = parse_options(args, 4);
        const auto session = find_session_by_id(repository, session_id);
        if (!session.has_value()) {
            fail("session not found");
        }
        print_session_target("revoke", *session);
        if (dry_run_requested(options)) {
            audit_cli_success(
                audit_repository, "cli_user_revoke_session_dry_run", "session",
                std::to_string(session_id), args,
                session_operation_details_json(
                    session_id, session->user_id, true,
                    flag_option_enabled(options, "--force")));
            std::cout << "dry-run: no session revoked\n";
            return;
        }
        require_force_for_destructive_command(options, "user revoke-session");
        repository.revoke_user_session_by_id(session_id);
        audit_cli_success(audit_repository, "cli_user_revoke_session", "session",
                          std::to_string(session_id), args,
                          session_operation_details_json(session_id,
                                                         session->user_id,
                                                         false, true));
        std::cout << "revoked session\n";
        return;
    }

    if (action == "revoke-all-sessions") {
        const auto user_id = parse_int64(args[3], "user id");
        const auto options = parse_options(args, 4);
        const auto user = find_user_by_id(repository, user_id);
        if (!user.has_value()) {
            fail("user not found");
        }
        const auto session_count = active_session_count(repository, user_id);
        print_user_target("revoke-all-sessions", *user, session_count);
        if (dry_run_requested(options)) {
            audit_cli_success(
                audit_repository, "cli_user_revoke_all_sessions_dry_run",
                "user", std::to_string(user_id), args,
                user_operation_details_json(user_id, session_count, true,
                                            flag_option_enabled(options,
                                                                "--force")));
            std::cout << "dry-run: no sessions revoked\n";
            return;
        }
        require_force_for_destructive_command(options,
                                              "user revoke-all-sessions");
        repository.revoke_all_user_sessions(user_id);
        audit_cli_success(audit_repository, "cli_user_revoke_all_sessions", "user",
                          std::to_string(user_id), args,
                          user_operation_details_json(user_id, session_count,
                                                      false, true));
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
        audit_cli_success(audit_repository, "cli_user_add", "user",
                          std::to_string(user_id), args);
        std::cout << "created user id=" << user_id << '\n';
        return;
    }

    if (action == "set-password") {
        const auto options = parse_options(args, 4);
        const auto user_id = parse_int64(args[3], "user id");
        const auto user = find_user_by_id(repository, user_id);
        if (!user.has_value()) {
            fail("user not found");
        }
        const auto session_count = active_session_count(repository, user_id);
        print_user_target("set-password", *user, session_count);
        if (dry_run_requested(options)) {
            audit_cli_success(
                audit_repository, "cli_user_set_password_dry_run", "user",
                std::to_string(user_id), args,
                user_operation_details_json(user_id, session_count, true,
                                            flag_option_enabled(options,
                                                                "--force")));
            std::cout << "dry-run: no password changed and no sessions revoked\n";
            return;
        }
        require_force_for_destructive_command(options, "user set-password");
        const auto password = option_or_prompt_password(options);
        repository.upsert_user_credential(user_id,
                                          roche_limit::auth_core::hash_password(password));
        repository.revoke_all_user_sessions(user_id);
        audit_cli_success(audit_repository, "cli_user_set_password", "user",
                          std::to_string(user_id), args,
                          user_operation_details_json(user_id, session_count,
                                                      false, true));
        std::cout << "updated user password\n";
        return;
    }

    if (action == "disable") {
        const auto user_id = parse_int64(args[3], "user id");
        const auto options = parse_options(args, 4);
        const auto user = find_user_by_id(repository, user_id);
        if (!user.has_value()) {
            fail("user not found");
        }
        const auto session_count = active_session_count(repository, user_id);
        print_user_target("disable", *user, session_count);
        if (dry_run_requested(options)) {
            audit_cli_success(audit_repository, "cli_user_disable_dry_run",
                              "user", std::to_string(user_id), args,
                              user_operation_details_json(
                                  user_id, session_count, true,
                                  flag_option_enabled(options, "--force")));
            std::cout << "dry-run: no user disabled and no sessions revoked\n";
            return;
        }
        require_force_for_destructive_command(options, "user disable");
        repository.update_user(user_id, UpdateUserRecord{
            .enabled = false,
        });
        repository.revoke_all_user_sessions(user_id);
        audit_cli_success(audit_repository, "cli_user_disable", "user",
                          std::to_string(user_id), args,
                          user_operation_details_json(user_id, session_count,
                                                      false, true));
        std::cout << "disabled user\n";
        return;
    }

    if (action == "remove") {
        const auto user_id = parse_int64(args[3], "user id");
        const auto options = parse_options(args, 4);
        const auto user = find_user_by_id(repository, user_id);
        if (!user.has_value()) {
            fail("user not found");
        }
        const auto session_count = active_session_count(repository, user_id);
        print_user_target("remove", *user, session_count);
        if (dry_run_requested(options)) {
            audit_cli_success(audit_repository, "cli_user_remove_dry_run",
                              "user", std::to_string(user_id), args,
                              user_operation_details_json(
                                  user_id, session_count, true,
                                  flag_option_enabled(options, "--force")));
            std::cout << "dry-run: no user deleted\n";
            return;
        }
        require_force_for_destructive_command(options, "user remove");
        repository.delete_user(user_id);
        audit_cli_success(audit_repository, "cli_user_remove", "user",
                          std::to_string(user_id), args,
                          user_operation_details_json(user_id, session_count,
                                                      false, true));
        std::cout << "deleted user\n";
        return;
    }

    if (action != "set") {
        fail("unknown user subcommand");
    }

    const auto options = parse_options(args, 4);
    const auto user_id = parse_int64(args[3], "user id");
    const auto user = find_user_by_id(repository, user_id);
    if (!user.has_value()) {
        fail("user not found");
    }
    const auto session_count = active_session_count(repository, user_id);
    const bool updates_service_level = options.contains("--level") || options.contains("--service");
    if (updates_service_level) {
        const auto level_option = optional_option(options, "--level");
        if (!level_option.has_value()) {
            fail("user service level update requires --level");
        }
        print_user_target("set-service-level", *user, session_count);
        if (dry_run_requested(options)) {
            audit_cli_success(
                audit_repository, "cli_user_service_level_upsert_dry_run",
                "user", std::to_string(user_id), args,
                user_operation_details_json(user_id, session_count, true,
                                            flag_option_enabled(options,
                                                                "--force")));
            std::cout << "dry-run: no service level changed and no sessions revoked\n";
            return;
        }
        require_force_for_destructive_command(options,
                                              "user set service level");
        const auto record_id = repository.upsert_user_service_level(NewUserServiceLevel{
            .user_id = user_id,
            .service_name = optional_option(options, "--service").value_or("*"),
            .access_level = parse_int(*level_option, "--level"),
            .note = optional_option(options, "--note"),
        });
        repository.revoke_all_user_sessions(user_id);
        audit_cli_success(audit_repository, "cli_user_service_level_upsert",
                          "user", std::to_string(user_id), args,
                          std::string("{\"record_id\":") +
                              std::to_string(record_id) +
                              ",\"active_sessions\":" +
                              std::to_string(session_count) +
                              ",\"dry_run\":false,\"force\":true}");
        std::cout << "upserted user service level id=" << record_id << '\n';
        return;
    }

    const bool enable = options.contains("--enable");
    const bool disable = options.contains("--disable");
    if (enable && disable) {
        fail("user set accepts only one of --enable or --disable");
    }
    if (enable || disable) {
        print_user_target(enable ? "enable" : "disable", *user, session_count);
        if (dry_run_requested(options)) {
            audit_cli_success(audit_repository, "cli_user_update_dry_run",
                              "user", std::to_string(user_id), args,
                              user_operation_details_json(
                                  user_id, session_count, true,
                                  flag_option_enabled(options, "--force")));
            std::cout << "dry-run: no user changed and no sessions revoked\n";
            return;
        }
        require_force_for_destructive_command(options, "user set enable/disable");
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
    audit_cli_success(audit_repository, "cli_user_update", "user",
                      std::to_string(user_id), args,
                      user_operation_details_json(user_id, session_count,
                                                  false,
                                                  enable || disable));
    std::cout << "updated user\n";
}

}  // namespace roche_limit::cli
