#include "auth_store/rule_repository.h"

#include "auth_store/sqlite_connection.h"
#include "common/debug_log.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace roche_limit::auth_store {

namespace {

using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleRecord;
using roche_limit::auth_core::IpRuleType;
using roche_limit::auth_core::IpServiceLevelRecord;
using roche_limit::auth_store::NewIpRule;
using roche_limit::auth_store::NewIpServiceLevel;
using roche_limit::auth_store::UpdateIpRule;

IpRuleEffect parse_effect(const std::string& effect_text) {
    if (effect_text == "allow") {
        return IpRuleEffect::Allow;
    }
    if (effect_text == "deny") {
        return IpRuleEffect::Deny;
    }
    throw std::runtime_error("unknown ip rule effect: " + effect_text);
}

AddressFamily parse_address_family(const std::string& family_text) {
    if (family_text == "ipv4") {
        return AddressFamily::IPv4;
    }
    if (family_text == "ipv6") {
        return AddressFamily::IPv6;
    }
    throw std::runtime_error("unknown address family: " + family_text);
}

IpRuleType parse_rule_type(const std::string& rule_type_text) {
    if (rule_type_text == "single") {
        return IpRuleType::Single;
    }
    if (rule_type_text == "cidr") {
        return IpRuleType::Cidr;
    }
    throw std::runtime_error("unknown ip rule type: " + rule_type_text);
}

std::string to_string(IpRuleEffect effect) {
    return effect == IpRuleEffect::Allow ? "allow" : "deny";
}

std::string to_string(AddressFamily family) {
    return family == AddressFamily::IPv4 ? "ipv4" : "ipv6";
}

std::string to_string(IpRuleType rule_type) {
    return rule_type == IpRuleType::Single ? "single" : "cidr";
}

IpRuleRecord read_ip_rule(sqlite3_stmt* statement) {
    const auto* value_text = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
    const auto* address_family_text =
        reinterpret_cast<const char*>(sqlite3_column_text(statement, 2));
    const auto* rule_type_text = reinterpret_cast<const char*>(sqlite3_column_text(statement, 3));
    const auto* effect_text = reinterpret_cast<const char*>(sqlite3_column_text(statement, 5));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 8));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 9));

    return IpRuleRecord{
        .id = sqlite3_column_int64(statement, 0),
        .value_text = value_text != nullptr ? value_text : "",
        .address_family = parse_address_family(address_family_text != nullptr ? address_family_text : ""),
        .rule_type = parse_rule_type(rule_type_text != nullptr ? rule_type_text : ""),
        .prefix_length = sqlite3_column_type(statement, 4) == SQLITE_NULL
                             ? std::optional<int>{}
                             : std::optional<int>(sqlite3_column_int(statement, 4)),
        .effect = parse_effect(effect_text != nullptr ? effect_text : ""),
        .enabled = sqlite3_column_int(statement, 6) != 0,
        .note = nullable_text(statement, 7),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

IpServiceLevelRecord read_ip_service_level(sqlite3_stmt* statement) {
    const auto* service_name = reinterpret_cast<const char*>(sqlite3_column_text(statement, 2));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 6));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 7));

    return IpServiceLevelRecord{
        .id = sqlite3_column_int64(statement, 0),
        .ip_rule_id = sqlite3_column_int64(statement, 1),
        .service_name = service_name != nullptr ? service_name : "",
        .access_level = sqlite3_column_int(statement, 3),
        .enabled = sqlite3_column_int(statement, 4) != 0,
        .note = nullable_text(statement, 5),
        .created_at = created_at != nullptr ? created_at : "",
        .updated_at = updated_at != nullptr ? updated_at : "",
    };
}

}  // namespace

RuleRepository::RuleRepository(std::filesystem::path database_path)
    : database_path_(std::move(database_path)) {}

std::vector<IpRuleRecord> RuleRepository::list_ip_rules(IpRuleEffect effect) const {
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_store] list_ip_rules begin effect="
                  << (effect == IpRuleEffect::Allow ? "allow" : "deny") << std::endl;
    }
    static constexpr auto kSql = R"SQL(
SELECT id, value_text, address_family, rule_type, prefix_length, effect, enabled, note, created_at, updated_at
FROM ip_rules
WHERE effect = ?1 AND enabled = 1
ORDER BY prefix_length DESC, id ASC;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, effect == IpRuleEffect::Allow ? "allow" : "deny");

    std::vector<IpRuleRecord> results;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to fetch ip rules");
        }
        results.push_back(read_ip_rule(statement.get()));
    }

    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_store] list_ip_rules done count=" << results.size() << std::endl;
    }
    return results;
}

std::optional<IpServiceLevelRecord> RuleRepository::find_ip_service_level(
    std::int64_t ip_rule_id,
    std::string_view service_name) const {
    static constexpr auto kSql = R"SQL(
SELECT id, ip_rule_id, service_name, access_level, enabled, note, created_at, updated_at
FROM ip_service_levels
WHERE ip_rule_id = ?1
  AND enabled = 1
  AND (service_name = ?2 OR service_name = '*')
ORDER BY CASE WHEN service_name = ?2 THEN 0 ELSE 1 END, id ASC
LIMIT 1;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, ip_rule_id);
    bind_text(statement.get(), 2, service_name);

    const auto step_result = sqlite3_step(statement.get());
    if (step_result == SQLITE_DONE) {
        return std::nullopt;
    }
    if (step_result != SQLITE_ROW) {
        throw std::runtime_error("failed to fetch ip service level");
    }

    return read_ip_service_level(statement.get());
}

std::optional<IpRuleRecord> RuleRepository::find_allow_ip_rule_by_value(
    std::string_view value_text) const {
    static constexpr auto kSql = R"SQL(
SELECT id, value_text, address_family, rule_type, prefix_length, effect, enabled, note, created_at, updated_at
FROM ip_rules
WHERE value_text = ?1 AND effect = 'allow' AND enabled = 1
ORDER BY id ASC;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, value_text);

    std::optional<IpRuleRecord> result;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to fetch allow ip rule by value");
        }

        if (result.has_value()) {
            throw std::runtime_error("multiple enabled allow ip rules share the same value_text");
        }
        result = read_ip_rule(statement.get());
    }

    return result;
}

std::vector<IpServiceLevelRecord> RuleRepository::list_ip_service_levels() const {
    static constexpr auto kSql = R"SQL(
SELECT id, ip_rule_id, service_name, access_level, enabled, note, created_at, updated_at
FROM ip_service_levels
ORDER BY service_name ASC, ip_rule_id ASC, id ASC;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);

    std::vector<IpServiceLevelRecord> results;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to list ip service levels");
        }
        results.push_back(read_ip_service_level(statement.get()));
    }

    return results;
}

std::int64_t RuleRepository::insert_ip_rule(const NewIpRule& new_ip_rule) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO ip_rules (
    value_text,
    address_family,
    rule_type,
    prefix_length,
    effect,
    note
) VALUES (?1, ?2, ?3, ?4, ?5, ?6);
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, new_ip_rule.value_text);
    bind_text(statement.get(), 2, to_string(new_ip_rule.address_family));
    bind_text(statement.get(), 3, to_string(new_ip_rule.rule_type));
    bind_nullable_int(statement.get(), 4, new_ip_rule.prefix_length);
    bind_text(statement.get(), 5, to_string(new_ip_rule.effect));
    bind_nullable_text(statement.get(), 6, new_ip_rule.note);
    step_done_or_throw(statement.get(), "failed to insert ip rule");

    return sqlite3_last_insert_rowid(connection.handle());
}

void RuleRepository::update_ip_rule(std::int64_t ip_rule_id, const UpdateIpRule& update_ip_rule) const {
    std::vector<std::string> assignments;
    if (update_ip_rule.value_text.has_value()) {
        assignments.emplace_back("value_text = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_ip_rule.address_family.has_value()) {
        assignments.emplace_back("address_family = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_ip_rule.rule_type.has_value()) {
        assignments.emplace_back("rule_type = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_ip_rule.prefix_length.has_value()) {
        assignments.emplace_back("prefix_length = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_ip_rule.effect.has_value()) {
        assignments.emplace_back("effect = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_ip_rule.note_is_set) {
        assignments.emplace_back("note = ?" + std::to_string(assignments.size() + 1));
    }
    if (assignments.empty()) {
        throw std::runtime_error("update_ip_rule requires at least one changed field");
    }

    std::string sql = "UPDATE ip_rules SET ";
    for (std::size_t index = 0; index < assignments.size(); ++index) {
        if (index > 0) {
            sql += ", ";
        }
        sql += assignments[index];
    }
    sql += ", updated_at = CURRENT_TIMESTAMP WHERE id = ?" + std::to_string(assignments.size() + 1) + ";";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), sql.c_str());

    int bind_index = 1;
    if (update_ip_rule.value_text.has_value()) {
        bind_text(statement.get(), bind_index++, *update_ip_rule.value_text);
    }
    if (update_ip_rule.address_family.has_value()) {
        bind_text(statement.get(), bind_index++, to_string(*update_ip_rule.address_family));
    }
    if (update_ip_rule.rule_type.has_value()) {
        bind_text(statement.get(), bind_index++, to_string(*update_ip_rule.rule_type));
    }
    if (update_ip_rule.prefix_length.has_value()) {
        if (sqlite3_bind_int(statement.get(), bind_index++, *update_ip_rule.prefix_length) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite integer parameter");
        }
    }
    if (update_ip_rule.effect.has_value()) {
        bind_text(statement.get(), bind_index++, to_string(*update_ip_rule.effect));
    }
    if (update_ip_rule.note_is_set) {
        bind_nullable_text(statement.get(), bind_index++, update_ip_rule.note);
    }
    bind_int64(statement.get(), bind_index, ip_rule_id);
    step_done_or_throw(statement.get(), "failed to update ip rule");
}

void RuleRepository::delete_ip_rule(std::int64_t ip_rule_id) const {
    static constexpr auto kDeleteServiceLevelsSql =
        "DELETE FROM ip_service_levels WHERE ip_rule_id = ?1;";
    static constexpr auto kDeleteRuleSql = "DELETE FROM ip_rules WHERE id = ?1;";

    SqliteConnection connection(database_path_);
    {
        Statement statement(connection.handle(), kDeleteServiceLevelsSql);
        bind_int64(statement.get(), 1, ip_rule_id);
        step_done_or_throw(statement.get(), "failed to delete ip service levels");
    }
    {
        Statement statement(connection.handle(), kDeleteRuleSql);
        bind_int64(statement.get(), 1, ip_rule_id);
        step_done_or_throw(statement.get(), "failed to delete ip rule");
    }
}

std::int64_t RuleRepository::upsert_ip_service_level(
    const NewIpServiceLevel& new_ip_service_level) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO ip_service_levels (
    ip_rule_id,
    service_name,
    access_level,
    note
) VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(ip_rule_id, service_name) DO UPDATE SET
    access_level = excluded.access_level,
    note = excluded.note,
    enabled = 1,
    updated_at = CURRENT_TIMESTAMP
RETURNING id;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, new_ip_service_level.ip_rule_id);
    bind_text(statement.get(), 2, new_ip_service_level.service_name);
    if (sqlite3_bind_int(statement.get(), 3, new_ip_service_level.access_level) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
    bind_nullable_text(statement.get(), 4, new_ip_service_level.note);

    const auto step_result = sqlite3_step(statement.get());
    if (step_result != SQLITE_ROW) {
        throw std::runtime_error("failed to upsert ip service level");
    }

    return sqlite3_column_int64(statement.get(), 0);
}

void RuleRepository::delete_ip_service_level(std::int64_t ip_rule_id,
                                             std::string_view service_name) const {
    static constexpr auto kSql =
        "DELETE FROM ip_service_levels WHERE ip_rule_id = ?1 AND service_name = ?2;";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, ip_rule_id);
    bind_text(statement.get(), 2, service_name);
    step_done_or_throw(statement.get(), "failed to delete ip service level");
}

}  // namespace roche_limit::auth_store
