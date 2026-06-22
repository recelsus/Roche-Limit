#include "cert_command.h"

#include "audit_logging.h"
#include "auth_core/access_level.h"
#include "cli_support.h"

#include <cctype>
#include <iostream>
#include <optional>

namespace roche_limit::cli {

using roche_limit::auth_core::ClientCertRecord;
using roche_limit::auth_core::ClientCertServiceLevelRecord;
using roche_limit::auth_store::NewClientCert;
using roche_limit::auth_store::NewClientCertServiceLevel;
using roche_limit::auth_store::RuleRepository;

namespace {

std::string display_value(const std::optional<std::string> &value) {
  return value.has_value() ? *value : "-";
}

std::string display_time(const std::optional<std::string> &value) {
  return value.has_value() ? *value : "-";
}

std::string service_level_name(const OptionsMap &options) {
  const auto service = optional_option(options, "--service");
  if (!service.has_value() || *service == "*" || *service == "all") {
    return "*";
  }
  return *service;
}

std::string normalize_fingerprint(std::string_view raw_fingerprint) {
  std::string normalized;
  for (const unsigned char ch : raw_fingerprint) {
    if (ch == ':' || std::isspace(ch)) {
      continue;
    }
    if (!std::isxdigit(ch)) {
      fail("client certificate fingerprint must be SHA-256 hex");
    }
    normalized.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  if (normalized.size() != 64) {
    fail("client certificate fingerprint must be 64 hex characters");
  }
  return normalized;
}

std::string cert_operation_details_json(std::int64_t cert_id, bool dry_run,
                                        bool force) {
  return std::string("{\"client_cert_id\":") + std::to_string(cert_id) +
         ",\"dry_run\":" + (dry_run ? "true" : "false") +
         ",\"force\":" + (force ? "true" : "false") + "}";
}

void print_cert_target(std::string_view operation,
                       const ClientCertRecord &record) {
  std::cout << operation << " client cert target\n";
  print_table({"id", "fingerprint", "status", "last_used", "last_ip", "note"},
              {{
                  std::to_string(record.id),
                  record.fingerprint_sha256,
                  bool_label(record.enabled),
                  display_time(record.last_used_at),
                  display_value(record.last_used_ip),
                  display_value(record.note),
              }});
}

void print_cert_list(const RuleRepository &repository) {
  const auto certs = repository.list_client_certs();
  std::vector<std::vector<std::string>> rows;
  for (const auto &record : certs) {
    rows.push_back({
        std::to_string(record.id),
        record.fingerprint_sha256,
        bool_label(record.enabled),
        display_time(record.not_after),
        display_time(record.last_used_at),
        display_value(record.last_used_ip),
        display_value(record.note),
    });
  }
  print_table({"id", "fingerprint", "status", "not_after", "last_used",
               "last_ip", "note"},
              rows);

  const auto service_levels = repository.list_client_cert_service_levels();
  if (service_levels.empty()) {
    return;
  }
  std::cout << '\n';
  std::vector<std::vector<std::string>> level_rows;
  for (const auto &record : service_levels) {
    level_rows.push_back({
        std::to_string(record.id),
        std::to_string(record.client_cert_id),
        printable_service_name(std::string_view(record.service_name)),
        std::to_string(record.access_level),
        bool_label(record.enabled),
        display_value(record.note),
    });
  }
  print_table({"id", "cert_id", "service", "level", "status", "note"},
              level_rows);
}

} // namespace

void handle_cert_command(
    const RuleRepository &repository,
    const roche_limit::auth_store::AuditRepository &audit_repository,
    const std::vector<std::string> &args) {
  if (args.size() < 3) {
    fail("missing cert subcommand");
  }

  const auto &action = args[2];
  if (action == "list") {
    print_cert_list(repository);
    return;
  }

  if (action == "add") {
    const auto options = parse_options(args, 4);
    const auto fingerprint = normalize_fingerprint(args[3]);
    const int access_level =
        optional_option(options, "--level").has_value()
            ? parse_int(*optional_option(options, "--level"), "--level")
            : roche_limit::auth_core::default_api_key_access_level();
    const auto cert_id = repository.insert_client_cert(NewClientCert{
        .fingerprint_sha256 = fingerprint,
        .serial_number = optional_option(options, "--serial"),
        .subject_dn = optional_option(options, "--subject"),
        .issuer_dn = optional_option(options, "--issuer"),
        .not_before = optional_option(options, "--not-before"),
        .not_after = optional_option(options, "--not-after"),
        .note = optional_option(options, "--note"),
    });
    const auto level_id =
        repository.upsert_client_cert_service_level(NewClientCertServiceLevel{
            .client_cert_id = cert_id,
            .service_name = service_level_name(options),
            .access_level = access_level,
            .note = optional_option(options, "--note"),
        });
    audit_cli_success(
        audit_repository, "cli_client_cert_add", "client_cert",
        std::to_string(cert_id), args,
        std::string("{\"client_cert_id\":") + std::to_string(cert_id) +
            ",\"service_level_id\":" + std::to_string(level_id) + "}");
    std::cout << "created client cert id=" << cert_id
              << " service_level_id=" << level_id << '\n';
    return;
  }

  if (action == "set") {
    const auto cert_id = parse_int64(args[3], "client cert id");
    const auto options = parse_options(args, 4);
    const auto current = repository.get_client_cert(cert_id);
    if (!current.has_value()) {
      fail("client cert not found");
    }
    const int access_level =
        optional_option(options, "--level").has_value()
            ? parse_int(*optional_option(options, "--level"), "--level")
            : 0;
    if (!optional_option(options, "--level").has_value()) {
      fail("cert set requires --level");
    }
    const auto level_id =
        repository.upsert_client_cert_service_level(NewClientCertServiceLevel{
            .client_cert_id = cert_id,
            .service_name = service_level_name(options),
            .access_level = access_level,
            .note = optional_option(options, "--note"),
        });
    audit_cli_success(
        audit_repository, "cli_client_cert_update", "client_cert",
        std::to_string(cert_id), args,
        std::string("{\"client_cert_id\":") + std::to_string(cert_id) +
            ",\"service_level_id\":" + std::to_string(level_id) + "}");
    std::cout << "upserted client cert service level id=" << level_id << '\n';
    return;
  }

  if (action == "disable" || action == "enable" || action == "remove") {
    const auto cert_id = parse_int64(args[3], "client cert id");
    const auto options = parse_options(args, 4);
    const auto current = repository.get_client_cert(cert_id);
    if (!current.has_value()) {
      fail("client cert not found");
    }
    print_cert_target(action, *current);
    const bool dry_run = dry_run_requested(options);
    if (dry_run) {
      audit_cli_success(
          audit_repository,
          action == "disable" ? "cli_client_cert_disable_dry_run"
          : action == "enable" ? "cli_client_cert_enable_dry_run"
                               : "cli_client_cert_remove_dry_run",
          "client_cert", std::to_string(cert_id), args,
          cert_operation_details_json(
              cert_id, true, flag_option_enabled(options, "--force")));
      std::cout << "dry-run: no client cert changed\n";
      return;
    }
    require_force_for_destructive_command(options,
                                          std::string("cert ") + action);
    if (action == "disable") {
      repository.disable_client_cert(cert_id);
      audit_cli_success(audit_repository, "cli_client_cert_disable",
                        "client_cert", std::to_string(cert_id), args,
                        cert_operation_details_json(cert_id, false, true));
      std::cout << "disabled client cert\n";
      return;
    }
    if (action == "enable") {
      repository.enable_client_cert(cert_id);
      audit_cli_success(audit_repository, "cli_client_cert_enable",
                        "client_cert", std::to_string(cert_id), args,
                        cert_operation_details_json(cert_id, false, true));
      std::cout << "enabled client cert\n";
      return;
    }
    repository.delete_client_cert(cert_id);
    audit_cli_success(audit_repository, "cli_client_cert_remove",
                      "client_cert", std::to_string(cert_id), args,
                      cert_operation_details_json(cert_id, false, true));
    std::cout << "deleted client cert\n";
    return;
  }

  fail("unknown cert subcommand");
}

} // namespace roche_limit::cli
