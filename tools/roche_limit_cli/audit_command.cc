#include "audit_command.h"

#include "audit_logging.h"
#include "cli_support.h"

#include <iostream>

namespace roche_limit::cli {

namespace {

std::string printable(const std::optional<std::string> &value) {
  return value.value_or("-");
}

std::string printable(const std::optional<int> &value) {
  return value.has_value() ? std::to_string(*value) : "-";
}

std::string identity(std::string_view type,
                     const std::optional<std::string> &id) {
  return id.has_value() ? std::string(type) + ":" + *id : std::string(type);
}

std::string target_identity(const std::optional<std::string> &type,
                            const std::optional<std::string> &id) {
  if (!type.has_value()) {
    return "-";
  }
  return identity(*type, id);
}

void print_event(const roche_limit::auth_store::AuditEventRecord &event) {
  print_table(
      {"field", "value"},
      {
          {"id", std::to_string(event.id)},
          {"created_at", event.created_at},
          {"event_type", event.event_type},
          {"actor_type", event.actor_type},
          {"actor_id", printable(event.actor_id)},
          {"target_type", printable(event.target_type)},
          {"target_id", printable(event.target_id)},
          {"service_name", printable(event.service_name)},
          {"access_level", printable(event.access_level)},
          {"client_ip", printable(event.client_ip)},
          {"request_id", printable(event.request_id)},
          {"result", event.result},
          {"reason", printable(event.reason)},
          {"metadata_json", printable(event.metadata_json)},
          {"prev_event_hash", printable(event.prev_event_hash)},
          {"event_hash", event.event_hash},
      });
}

} // namespace

void handle_audit_command(
    const roche_limit::auth_store::AuditRepository &audit_repository,
    const std::vector<std::string> &args) {
  if (args.size() < 3) {
    fail("missing audit subcommand");
  }

  const auto &action = args[2];
  if (action == "show") {
    if (args.size() != 4) {
      fail("usage: roche_limit_cli audit show <event-id>");
    }
    const auto event = audit_repository.get_event(parse_int64(args[3], "event-id"));
    if (!event.has_value()) {
      fail("audit event not found");
    }
    print_event(*event);
    return;
  }

  const auto options = parse_options(args, 3);
  if (action == "list") {
    const int limit = optional_option(options, "--limit").has_value()
                          ? parse_int(*optional_option(options, "--limit"),
                                      "--limit")
                          : 50;
    if (limit < 1 || limit > 500) {
      fail("--limit must be between 1 and 500");
    }
    const auto events = audit_repository.list_events(
        roche_limit::auth_store::AuditEventFilter{
            .limit = limit,
            .event_type = optional_option(options, "--event-type"),
            .result = optional_option(options, "--result"),
            .service_name = optional_option(options, "--service"),
            .request_id = optional_option(options, "--request-id"),
            .actor_type = optional_option(options, "--actor-type"),
            .reason = optional_option(options, "--reason"),
            .client_ip = optional_option(options, "--client-ip"),
        });
    std::vector<std::vector<std::string>> rows;
    rows.reserve(events.size());
    for (const auto &event : events) {
      rows.push_back({
          std::to_string(event.id),
          event.created_at,
          event.event_type,
          identity(event.actor_type, event.actor_id),
          target_identity(event.target_type, event.target_id),
          printable(event.service_name),
          printable(event.access_level),
          printable(event.client_ip),
          event.result,
          printable(event.reason),
          printable(event.request_id),
      });
    }
    print_table({"id", "created_at", "event_type", "actor", "target",
                 "service", "level", "client_ip", "result", "reason",
                 "request_id"},
                rows);
    return;
  }

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
