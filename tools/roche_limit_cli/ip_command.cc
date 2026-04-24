#include "ip_command.h"

#include "audit_logging.h"
#include "auth_core/ip_rule_record.h"
#include "cli_support.h"

#include <algorithm>
#include <iostream>

namespace roche_limit::cli {

using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpServiceLevelRecord;
using roche_limit::auth_store::NewIpRule;
using roche_limit::auth_store::NewIpServiceLevel;
using roche_limit::auth_store::RuleRepository;
using roche_limit::auth_store::UpdateIpRule;

void handle_ip_command(
    const RuleRepository& repository,
    const roche_limit::auth_store::AuditRepository& audit_repository,
    const std::vector<std::string>& args) {
    if (args.size() < 3) {
        fail("missing ip subcommand");
    }

    const auto& action = args[2];
    if (action == "list") {
        std::vector<std::vector<std::string>> rows;
        for (const auto effect : {IpRuleEffect::Deny, IpRuleEffect::Allow}) {
            const auto rules = repository.list_ip_rules(effect);
            for (const auto& rule : rules) {
                rows.push_back({
                    std::to_string(rule.id),
                    to_string(rule.effect),
                    rule.value_text,
                    to_string(rule.address_family),
                    to_string(rule.rule_type),
                    rule.prefix_length.has_value() ? std::to_string(*rule.prefix_length) : "-",
                    bool_label(rule.enabled),
                });
            }
        }
        print_table({"id", "effect", "value", "family", "type", "prefix", "status"}, rows);

        const auto service_levels = repository.list_ip_service_levels();
        if (!service_levels.empty()) {
            std::cout << '\n';
            std::vector<std::vector<std::string>> level_rows;
            for (const auto& record : service_levels) {
                level_rows.push_back({
                    std::to_string(record.id),
                    std::to_string(record.ip_rule_id),
                    printable_service_name(std::string_view(record.service_name)),
                    std::to_string(record.access_level),
                    bool_label(record.enabled),
                    record.note.has_value() ? *record.note : "-",
                });
            }
            print_table({"id", "ip_rule_id", "service", "level", "status", "note"}, level_rows);
        }
        return;
    }

    if (action == "remove") {
        if (args.size() < 4) {
            fail("missing ip rule id");
        }
        const auto rule_id = parse_int64(args[3], "ip rule id");
        repository.delete_ip_rule(rule_id);
        audit_cli_success(audit_repository, "cli_ip_remove", "ip_rule",
                          std::to_string(rule_id), args);
        std::cout << "deleted ip rule\n";
        return;
    }

    if (action == "compact-ids") {
        require_experimental_cli("ip compact-ids");
        repository.compact_ip_ids();
        audit_cli_success(audit_repository, "cli_ip_compact_ids", "ip_rule",
                          std::nullopt, args);
        std::cout << "compacted ip ids\n";
        return;
    }

    if (args.size() < 4) {
        fail("missing ip value");
    }

    const auto target = args[3];
    const auto options = parse_options(args, 4);
    if (action == "add") {
        const auto parsed_ip = parse_cli_ip(target);
        const bool allow = options.contains("--allow");
        const bool deny = options.contains("--deny");
        if (allow == deny) {
            fail("ip add requires exactly one of --allow or --deny");
        }

        const auto rule_id = repository.insert_ip_rule(NewIpRule{
            .value_text = target,
            .address_family = parsed_ip.family,
            .rule_type = parsed_ip.rule_type,
            .prefix_length = parsed_ip.prefix_length,
            .effect = allow ? IpRuleEffect::Allow : IpRuleEffect::Deny,
            .note = optional_option(options, "--note"),
        });
        audit_cli_success(audit_repository, "cli_ip_add", "ip_rule",
                          std::to_string(rule_id), args);
        std::cout << "created ip rule id=" << rule_id << '\n';
        return;
    }

    if (action != "set") {
        fail("unknown ip subcommand");
    }

    if (looks_like_ip_or_cidr(target)) {
        const auto matched_rule = repository.find_allow_ip_rule_by_value(target);
        if (!matched_rule.has_value()) {
            fail("ip set requires an existing allow ip rule");
        }

        const auto record_id = repository.upsert_ip_service_level(NewIpServiceLevel{
            .ip_rule_id = matched_rule->id,
            .service_name = optional_option(options, "--service").value_or("*"),
            .access_level = parse_int(require_option(options, "--level"), "--level"),
            .note = optional_option(options, "--note"),
        });
        audit_cli_success(audit_repository, "cli_ip_service_level_upsert",
                          "ip_service_level", std::to_string(record_id), args);
        std::cout << "upserted ip service level id=" << record_id << '\n';
        return;
    }

    const bool updates_service_level = options.contains("--level") || options.contains("--service");
    if (updates_service_level) {
        const auto ip_rule_id = parse_int64(target, "ip rule id");
        const auto service_levels = repository.list_ip_service_levels();

        std::optional<IpServiceLevelRecord> matched_record;
        std::string resolved_service_name = optional_option(options, "--service").value_or("");
        if (resolved_service_name == "all") {
            resolved_service_name = "*";
        }

        if (!resolved_service_name.empty()) {
            for (const auto& record : service_levels) {
                if (record.ip_rule_id == ip_rule_id && record.service_name == resolved_service_name &&
                    record.enabled) {
                    matched_record = record;
                    break;
                }
            }
        } else {
            std::vector<IpServiceLevelRecord> matched_records;
            for (const auto& record : service_levels) {
                if (record.ip_rule_id == ip_rule_id && record.enabled) {
                    matched_records.push_back(record);
                }
            }

            if (matched_records.size() == 1) {
                matched_record = matched_records.front();
                resolved_service_name = matched_record->service_name;
            } else {
                const auto wildcard_it = std::find_if(
                    matched_records.begin(),
                    matched_records.end(),
                    [](const IpServiceLevelRecord& record) { return record.service_name == "*"; });
                if (wildcard_it != matched_records.end()) {
                    matched_record = *wildcard_it;
                    resolved_service_name = "*";
                } else if (matched_records.empty()) {
                    resolved_service_name = "*";
                } else {
                    fail("multiple ip service levels exist for this ip rule; specify --service");
                }
            }
        }

        int access_level = 0;
        if (const auto level = optional_option(options, "--level"); level.has_value()) {
            access_level = parse_int(*level, "--level");
        } else if (matched_record.has_value()) {
            access_level = matched_record->access_level;
        } else {
            fail("ip service level update requires --level when no existing service-level record exists");
        }

        const auto record_id = repository.upsert_ip_service_level(NewIpServiceLevel{
            .ip_rule_id = ip_rule_id,
            .service_name = resolved_service_name.empty() ? "*" : resolved_service_name,
            .access_level = access_level,
            .note = optional_option(options, "--note"),
        });
        audit_cli_success(audit_repository, "cli_ip_service_level_upsert",
                          "ip_service_level", std::to_string(record_id), args);
        std::cout << "upserted ip service level id=" << record_id << '\n';
        return;
    }

    const bool allow = options.contains("--allow");
    const bool deny = options.contains("--deny");
    if (allow && deny) {
        fail("ip set accepts only one of --allow or --deny");
    }

    UpdateIpRule update_ip_rule{
        .note_is_set = options.contains("--note"),
        .note = optional_option(options, "--note"),
    };
    if (const auto value = optional_option(options, "--value"); value.has_value()) {
        const auto parsed_ip = parse_cli_ip(*value);
        update_ip_rule.value_text = *value;
        update_ip_rule.address_family = parsed_ip.family;
        update_ip_rule.rule_type = parsed_ip.rule_type;
        update_ip_rule.prefix_length = parsed_ip.prefix_length;
    }
    if (allow || deny) {
        update_ip_rule.effect = allow ? IpRuleEffect::Allow : IpRuleEffect::Deny;
    }
    repository.update_ip_rule(parse_int64(target, "ip rule id"), update_ip_rule);
    audit_cli_success(audit_repository, "cli_ip_update", "ip_rule", target,
                      args);
    std::cout << "updated ip rule\n";
}

}  // namespace roche_limit::cli
