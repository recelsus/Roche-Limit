#include "key_command.h"

#include "audit_logging.h"
#include "auth_core/access_level.h"
#include "auth_core/api_key_hasher.h"
#include "cli_support.h"

#include <algorithm>
#include <iostream>

namespace roche_limit::cli {

using roche_limit::auth_store::NewApiKeyRecord;
using roche_limit::auth_store::RuleRepository;
using roche_limit::auth_store::UpdateApiKeyRecord;

namespace {

std::string display_time(const std::optional<std::string> &value) {
  return value.has_value() ? *value : "-";
}

std::int64_t insert_generated_api_key(const RuleRepository &repository,
                                      std::string_view plain_api_key,
                                      const OptionsMap &options) {
  const auto level_option = optional_option(options, "--level");
  return repository.insert_api_key(NewApiKeyRecord{
      .key_hash = roche_limit::auth_core::hash_api_key(plain_api_key),
      .key_lookup_hash =
          roche_limit::auth_core::api_key_lookup_hash(plain_api_key),
      .key_prefix = roche_limit::auth_core::api_key_prefix(plain_api_key),
      .service_name = parse_service_name_option(options, "--service"),
      .access_level =
          level_option.has_value()
              ? parse_int(*level_option, "--level")
              : roche_limit::auth_core::default_api_key_access_level(),
      .expires_at = optional_option(options, "--expires-at"),
      .note = optional_option(options, "--note"),
  });
}

std::string generate_unique_api_key(const RuleRepository &repository) {
  for (int attempt = 0; attempt < 8; ++attempt) {
    const auto candidate = generate_api_key();
    const auto prefix = roche_limit::auth_core::api_key_prefix(candidate);
    const auto records = repository.list_api_keys();
    const bool collision = std::any_of(
        records.begin(), records.end(), [&prefix](const auto &record) {
          return record.key_prefix.has_value() && *record.key_prefix == prefix;
        });
    if (!collision) {
      return candidate;
    }
  }
  fail("failed to generate unique api key prefix");
}

} // namespace

void handle_key_command(
    const RuleRepository &repository,
    const roche_limit::auth_store::AuditRepository &audit_repository,
    const std::vector<std::string> &args) {
  if (args.size() < 3) {
    fail("missing key subcommand");
  }

  const auto &action = args[2];
  if (action == "list") {
    repository.disable_expired_api_keys();
    const auto records = repository.list_api_keys();
    std::vector<std::vector<std::string>> rows;
    for (const auto &record : records) {
      rows.push_back({
          std::to_string(record.id),
          record.key_prefix.has_value() ? *record.key_prefix : "-",
          printable_service_name(record.service_name),
          std::to_string(record.access_level),
          bool_label(record.enabled),
          display_time(record.expires_at),
          display_time(record.last_used_at),
          display_time(record.last_used_ip),
          std::to_string(record.failed_attempts),
          display_time(record.last_failed_at),
          record.note.has_value() ? *record.note : "-",
      });
    }
    print_table({"id", "prefix", "scope", "level", "status", "expires",
                 "last_used", "last_ip", "fails", "last_failed", "note"},
                rows);
    return;
  }

  if (action == "compact-ids") {
    require_experimental_cli("key compact-ids");
    repository.compact_api_key_ids();
    audit_cli_success(audit_repository, "cli_key_compact_ids", "api_key",
                      std::nullopt, args);
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
      audit_cli_success(audit_repository, "cli_key_disable", "api_key",
                        std::to_string(api_key_id), args);
      std::cout << "disabled api key\n";
      return;
    }
    if (action == "remove") {
      repository.delete_api_key(api_key_id);
      audit_cli_success(audit_repository, "cli_key_remove", "api_key",
                        std::to_string(api_key_id), args);
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
    const auto api_key_id = insert_generated_api_key(repository, plain_api_key,
                                                     options);
    audit_cli_success(audit_repository, "cli_key_add", "api_key",
                      std::to_string(api_key_id), args);
    std::cout << "created api key id=" << api_key_id << '\n';
    return;
  }

  if (action == "gen") {
    const auto plain_api_key = generate_unique_api_key(repository);
    const auto api_key_id = insert_generated_api_key(repository, plain_api_key,
                                                     options);
    audit_cli_success(audit_repository, "cli_key_gen", "api_key",
                      std::to_string(api_key_id), args);
    std::cout << "created api key id=" << api_key_id << '\n';
    std::cout << "plain=" << plain_api_key << '\n';
    std::cout << "note=plain key is shown only once\n";
    return;
  }

  if (action == "rotate") {
    if (args.size() < 4) {
      fail("missing api key id");
    }
    const auto api_key_id = parse_int64(args[3], "api key id");
    const auto current = repository.get_api_key(api_key_id);
    if (!current.has_value()) {
      fail("api key not found");
    }
    const auto plain_api_key = generate_unique_api_key(repository);
    const auto level_option = optional_option(options, "--level");
    const auto rotated_id = repository.insert_api_key(NewApiKeyRecord{
        .key_hash = roche_limit::auth_core::hash_api_key(plain_api_key),
        .key_lookup_hash =
            roche_limit::auth_core::api_key_lookup_hash(plain_api_key),
        .key_prefix = roche_limit::auth_core::api_key_prefix(plain_api_key),
        .service_name = options.contains("--service")
                            ? parse_service_name_option(options, "--service")
                            : current->service_name,
        .access_level = level_option.has_value()
                            ? parse_int(*level_option, "--level")
                            : current->access_level,
        .expires_at = options.contains("--expires-at")
                          ? optional_option(options, "--expires-at")
                          : current->expires_at,
        .note = options.contains("--note") ? optional_option(options, "--note")
                                           : current->note,
    });
    repository.disable_api_key(api_key_id);
    audit_cli_success(audit_repository, "cli_key_rotate", "api_key",
                      std::to_string(rotated_id), args,
                      std::string("{\"old_id\":") + std::to_string(api_key_id) +
                          ",\"new_id\":" + std::to_string(rotated_id) + "}");
    std::cout << "rotated api key old_id=" << api_key_id
              << " new_id=" << rotated_id << '\n';
    std::cout << "plain=" << plain_api_key << '\n';
    std::cout << "note=plain key is shown only once\n";
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
    if (const auto level = optional_option(options, "--level");
        level.has_value()) {
      update_api_key_record.access_level = parse_int(*level, "--level");
    }
    repository.update_api_key(parse_int64(args[3], "api key id"),
                              update_api_key_record);
    audit_cli_success(audit_repository, "cli_key_update", "api_key", args[3],
                      args);
    std::cout << "updated api key\n";
    return;
  }

  fail("unknown key subcommand");
}

} // namespace roche_limit::cli
