#include "audit_command.h"

#include "audit_logging.h"
#include "cli_support.h"

#include <iostream>

namespace roche_limit::cli {

void handle_audit_command(
    const roche_limit::auth_store::AuditRepository &audit_repository,
    const std::vector<std::string> &args) {
  if (args.size() < 3) {
    fail("missing audit subcommand");
  }

  const auto &action = args[2];
  const auto options = parse_options(args, 3);
  if (action == "cleanup") {
    const int retention_days =
        optional_option(options, "--retention-days").has_value()
            ? parse_int(*optional_option(options, "--retention-days"),
                        "--retention-days")
            : 90;
    const int max_rows = optional_option(options, "--max-rows").has_value()
                             ? parse_int(*optional_option(options, "--max-rows"),
                                         "--max-rows")
                             : 10000;
    const auto result = audit_repository.cleanup(retention_days, max_rows);
    audit_cli_success(
        audit_repository, "cli_audit_cleanup", "audit_events", std::nullopt,
        args,
        std::string("{\"retention_deleted_rows\":") +
            std::to_string(result.retention_deleted_rows) +
            ",\"overflow_deleted_rows\":" +
            std::to_string(result.overflow_deleted_rows) + "}");
    std::cout << "audit cleanup completed retention_deleted_rows="
              << result.retention_deleted_rows
              << " overflow_deleted_rows=" << result.overflow_deleted_rows
              << '\n';
    return;
  }

  fail("unknown audit subcommand");
}

} // namespace roche_limit::cli
