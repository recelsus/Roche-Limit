#include "audit_command.h"
#include "audit_logging.h"
#include "cert_command.h"
#include "cli_support.h"
#include "ip_command.h"
#include "key_command.h"
#include "auth_store/audit_repository.h"
#include "auth_store/rule_repository.h"
#include "auth_store/schema_bootstrap.h"
#include "auth_store/user_repository.h"
#include "user_command.h"
#include "common/debug_log.h"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using roche_limit::auth_store::RuleRepository;
using roche_limit::auth_store::UserRepository;
int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv, argv + argc);
    try {
        if (const auto verbose_it = std::find(args.begin(), args.end(), "--verbose");
            verbose_it != args.end()) {
            roche_limit::common::set_verbose_logging_enabled(true);
            args.erase(verbose_it);
        }
        if (args.size() < 2) {
            roche_limit::cli::print_usage();
            return 1;
        }

        if (roche_limit::cli::is_help_argument(args[1])) {
            roche_limit::cli::print_help(
                args.size() >= 3
                    ? std::optional<std::string_view>(args[2])
                    : std::nullopt,
                args.size() >= 4
                    ? std::optional<std::string_view>(args[3])
                    : std::nullopt);
            return 0;
        }
        if (args.size() >= 3 &&
            roche_limit::cli::is_help_argument(args[2])) {
            roche_limit::cli::print_help(args[1]);
            return 0;
        }
        if (args.size() >= 4 &&
            roche_limit::cli::is_help_argument(args.back())) {
            roche_limit::cli::print_help(args[1], args[2]);
            return 0;
        }

        const auto& domain = args[1];
        if (!roche_limit::cli::is_known_command_domain(domain)) {
            std::cerr << "roche-limit-cli: unknown command: " << domain << "\n\n";
            roche_limit::cli::print_usage();
            return 1;
        }
        if (args.size() < 3) {
            roche_limit::cli::print_help(domain);
            return 1;
        }
        const auto& action = args[2];
        if (!roche_limit::cli::is_known_command_action(domain, action)) {
            std::cerr << "roche-limit-cli: unknown " << domain
                      << " action: " << action << "\n\n";
            roche_limit::cli::print_help(domain);
            return 1;
        }
        if (args.size() < 4 &&
            roche_limit::cli::command_action_requires_target(domain, action)) {
            roche_limit::cli::print_help(domain, action);
            return 1;
        }

        const auto executable_path = argc > 0 ? std::filesystem::path(argv[0]) : std::filesystem::path{};
        const auto bootstrap_result = roche_limit::auth_store::bootstrap_sqlite_schema(executable_path);
        RuleRepository repository(bootstrap_result.database_path);
        UserRepository user_repository(bootstrap_result.database_path);
        roche_limit::auth_store::AuditRepository audit_repository(bootstrap_result.database_path);

        if (domain == "ip") {
            roche_limit::cli::handle_ip_command(repository, audit_repository, args);
            return 0;
        }
        if (domain == "key") {
            roche_limit::cli::handle_key_command(repository, audit_repository, args);
            return 0;
        }
        if (domain == "cert") {
            roche_limit::cli::handle_cert_command(repository, audit_repository, args);
            return 0;
        }
        if (domain == "audit") {
            roche_limit::cli::handle_audit_command(audit_repository, args);
            return 0;
        }
        if (domain == "user") {
            roche_limit::cli::handle_user_command(user_repository, audit_repository, args);
            return 0;
        }

        roche_limit::cli::print_usage();
        return 1;
    } catch (const std::exception& ex) {
        try {
            const auto executable_path = argc > 0 ? std::filesystem::path(argv[0]) : std::filesystem::path{};
            const auto bootstrap_result = roche_limit::auth_store::bootstrap_sqlite_schema(executable_path);
            roche_limit::auth_store::AuditRepository audit_repository(bootstrap_result.database_path);
            roche_limit::cli::audit_cli_error(audit_repository, args, "exception");
        } catch (...) {
        }
        std::cerr << "roche-limit-cli: " << ex.what() << std::endl;
        return 1;
    }
}
