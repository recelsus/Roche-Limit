#include "cli_support.h"
#include "ip_command.h"
#include "key_command.h"
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
    try {
        std::vector<std::string> args(argv, argv + argc);
        if (const auto verbose_it = std::find(args.begin(), args.end(), "--verbose");
            verbose_it != args.end()) {
            roche_limit::common::set_verbose_logging_enabled(true);
            args.erase(verbose_it);
        }
        if (args.size() < 2) {
            roche_limit::cli::print_usage();
            return 1;
        }

        const auto executable_path = argc > 0 ? std::filesystem::path(argv[0]) : std::filesystem::path{};
        const auto bootstrap_result = roche_limit::auth_store::bootstrap_sqlite_schema(executable_path);
        RuleRepository repository(bootstrap_result.database_path);
        UserRepository user_repository(bootstrap_result.database_path);

        const auto& domain = args[1];
        if (domain == "ip") {
            roche_limit::cli::handle_ip_command(repository, args);
            return 0;
        }
        if (domain == "key") {
            roche_limit::cli::handle_key_command(repository, args);
            return 0;
        }
        if (domain == "user") {
            roche_limit::cli::handle_user_command(user_repository, args);
            return 0;
        }

        roche_limit::cli::print_usage();
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "roche-limit-cli: " << ex.what() << std::endl;
        return 1;
    }
}
