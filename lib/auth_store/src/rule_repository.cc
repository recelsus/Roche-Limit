#include "auth_store/rule_repository.h"

#include "common/debug_log.h"
#include "auth_store/sqlite_connection.h"

#include <sqlite3.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace roche_limit::auth_store {

namespace {

using roche_limit::auth_core::AddressFamily;
using roche_limit::auth_core::ApiKeyRecord;
using roche_limit::auth_core::IpRuleEffect;
using roche_limit::auth_core::IpRuleRecord;
using roche_limit::auth_core::IpRuleType;
using roche_limit::auth_core::IpServiceLevelRecord;
using roche_limit::auth_store::NewApiKeyRecord;
using roche_limit::auth_store::NewIpRule;
using roche_limit::auth_store::NewIpServiceLevel;
using roche_limit::auth_store::UpdateApiKeyRecord;
using roche_limit::auth_store::UpdateIpRule;

class Statement final {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db_, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("failed to prepare sqlite statement: ") +
                                     sqlite3_errmsg(db_));
        }
    }

    ~Statement() {
        if (statement_ != nullptr) {
            sqlite3_finalize(statement_);
            statement_ = nullptr;
        }
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    sqlite3_stmt* get() const noexcept {
        return statement_;
    }

private:
    sqlite3* db_{nullptr};
    sqlite3_stmt* statement_{nullptr};
};

std::optional<std::string> nullable_text(sqlite3_stmt* statement, int column) {
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        return std::nullopt;
    }

    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    return text != nullptr ? std::optional<std::string>(text) : std::nullopt;
}

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

void bind_text(sqlite3_stmt* statement, int index, std::string_view value) {
    if (sqlite3_bind_text(statement,
                          index,
                          value.data(),
                          static_cast<int>(value.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite text parameter");
    }
}

void bind_nullable_text(sqlite3_stmt* statement, int index, const std::optional<std::string>& value) {
    if (!value.has_value()) {
        if (sqlite3_bind_null(statement, index) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite null parameter");
        }
        return;
    }

    bind_text(statement, index, *value);
}

void bind_int64(sqlite3_stmt* statement, int index, std::int64_t value) {
    if (sqlite3_bind_int64(statement, index, value) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
}

void bind_nullable_int(sqlite3_stmt* statement, int index, const std::optional<int>& value) {
    if (!value.has_value()) {
        if (sqlite3_bind_null(statement, index) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite null integer parameter");
        }
        return;
    }

    if (sqlite3_bind_int(statement, index, *value) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
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

void step_done_or_throw(sqlite3_stmt* statement, const std::string& message) {
    const auto step_result = sqlite3_step(statement);
    if (step_result != SQLITE_DONE) {
        throw std::runtime_error(message);
    }
}

void exec_sql(sqlite3* db, const char* sql, const char* message) {
    char* error_message = nullptr;
    const auto result = sqlite3_exec(db, sql, nullptr, nullptr, &error_message);
    if (result != SQLITE_OK) {
        std::string full_message = message;
        if (error_message != nullptr) {
            full_message += ": ";
            full_message += error_message;
            sqlite3_free(error_message);
        }
        throw std::runtime_error(full_message);
    }
}

std::vector<std::int64_t> select_ids(sqlite3* db, const char* sql, const char* message) {
    Statement statement(db, sql);
    std::vector<std::int64_t> ids;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error(message);
        }
        ids.push_back(sqlite3_column_int64(statement.get(), 0));
    }
    return ids;
}

void update_single_id(sqlite3* db,
                      const char* sql,
                      std::int64_t old_id,
                      std::int64_t new_id,
                      const char* message) {
    Statement statement(db, sql);
    bind_int64(statement.get(), 1, new_id);
    bind_int64(statement.get(), 2, old_id);
    step_done_or_throw(statement.get(), message);
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

ApiKeyRecord read_api_key(sqlite3_stmt* statement) {
    const auto* key_hash = reinterpret_cast<const char*>(sqlite3_column_text(statement, 2));
    const auto* created_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 9));
    const auto* updated_at = reinterpret_cast<const char*>(sqlite3_column_text(statement, 10));

    return ApiKeyRecord{
        .id = sqlite3_column_int64(statement, 0),
        .key_plain = nullable_text(statement, 1),
        .key_hash = key_hash != nullptr ? key_hash : "",
        .key_prefix = nullable_text(statement, 3),
        .service_name = nullable_text(statement, 4),
        .access_level = sqlite3_column_int(statement, 5),
        .enabled = sqlite3_column_int(statement, 6) != 0,
        .expires_at = nullable_text(statement, 7),
        .note = nullable_text(statement, 8),
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

std::optional<ApiKeyRecord> RuleRepository::find_api_key(
    std::string_view key_hash,
    std::string_view service_name) const {
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_store] find_api_key begin service=" << service_name << std::endl;
    }
    static constexpr auto kSql = R"SQL(
SELECT id, key_plain, key_hash, key_prefix, service_name, access_level, enabled, expires_at, note, created_at, updated_at
FROM api_keys
WHERE key_hash = ?1
  AND enabled = 1
  AND (service_name = ?2 OR service_name IS NULL)
ORDER BY CASE WHEN service_name = ?2 THEN 0 ELSE 1 END, id ASC
LIMIT 1;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_text(statement.get(), 1, key_hash);
    bind_text(statement.get(), 2, service_name);

    const auto step_result = sqlite3_step(statement.get());
    if (step_result == SQLITE_DONE) {
        if (roche_limit::common::verbose_logging_enabled()) {
            std::cerr << "[auth_store] find_api_key no match" << std::endl;
        }
        return std::nullopt;
    }
    if (step_result != SQLITE_ROW) {
        throw std::runtime_error("failed to fetch api key");
    }

    if (roche_limit::common::verbose_logging_enabled()) {
        std::cerr << "[auth_store] find_api_key matched" << std::endl;
    }
    return read_api_key(statement.get());
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

std::vector<ApiKeyRecord> RuleRepository::list_api_keys() const {
    static constexpr auto kSql = R"SQL(
SELECT id, key_plain, key_hash, key_prefix, service_name, access_level, enabled, expires_at, note, created_at, updated_at
FROM api_keys
ORDER BY key_hash ASC, service_name ASC, id ASC;
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);

    std::vector<ApiKeyRecord> results;
    while (true) {
        const auto step_result = sqlite3_step(statement.get());
        if (step_result == SQLITE_DONE) {
            break;
        }
        if (step_result != SQLITE_ROW) {
            throw std::runtime_error("failed to list api keys");
        }
        results.push_back(read_api_key(statement.get()));
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

void RuleRepository::compact_ip_ids() const {
    static constexpr auto kSelectRuleIdsSql = "SELECT id FROM ip_rules ORDER BY id ASC;";
    static constexpr auto kSelectServiceLevelIdsSql =
        "SELECT id FROM ip_service_levels ORDER BY id ASC;";
    static constexpr auto kUpdateRuleIdSql = "UPDATE ip_rules SET id = ?1 WHERE id = ?2;";
    static constexpr auto kUpdateServiceRuleIdSql =
        "UPDATE ip_service_levels SET ip_rule_id = ?1 WHERE ip_rule_id = ?2;";
    static constexpr auto kUpdateServiceLevelIdSql =
        "UPDATE ip_service_levels SET id = ?1 WHERE id = ?2;";

    SqliteConnection connection(database_path_);
    auto* db = connection.handle();
    exec_sql(db, "PRAGMA foreign_keys = OFF;", "failed to disable foreign keys");
    exec_sql(db, "BEGIN IMMEDIATE;", "failed to begin transaction");
    try {
        const auto rule_ids = select_ids(db, kSelectRuleIdsSql, "failed to load ip rule ids");
        for (std::size_t index = 0; index < rule_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateServiceRuleIdSql,
                             rule_ids[index],
                             temp_id,
                             "failed to move ip service level references");
            update_single_id(db, kUpdateRuleIdSql, rule_ids[index], temp_id, "failed to move ip rule id");
        }
        for (std::size_t index = 0; index < rule_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            const auto new_id = static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateServiceRuleIdSql,
                             temp_id,
                             new_id,
                             "failed to restore ip service level references");
            update_single_id(db, kUpdateRuleIdSql, temp_id, new_id, "failed to restore ip rule id");
        }

        const auto service_level_ids =
            select_ids(db, kSelectServiceLevelIdsSql, "failed to load ip service level ids");
        for (std::size_t index = 0; index < service_level_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateServiceLevelIdSql,
                             service_level_ids[index],
                             temp_id,
                             "failed to move ip service level id");
        }
        for (std::size_t index = 0; index < service_level_ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            const auto new_id = static_cast<std::int64_t>(index + 1);
            update_single_id(db,
                             kUpdateServiceLevelIdSql,
                             temp_id,
                             new_id,
                             "failed to restore ip service level id");
        }

        exec_sql(db, "COMMIT;", "failed to commit transaction");
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
        throw;
    }
    exec_sql(db, "PRAGMA foreign_keys = ON;", "failed to re-enable foreign keys");
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

std::int64_t RuleRepository::insert_api_key(const NewApiKeyRecord& new_api_key_record) const {
    static constexpr auto kSql = R"SQL(
INSERT INTO api_keys (
    key_plain,
    key_hash,
    key_prefix,
    service_name,
    access_level,
    expires_at,
    note
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
)SQL";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_nullable_text(statement.get(), 1, new_api_key_record.key_plain);
    bind_text(statement.get(), 2, new_api_key_record.key_hash);
    bind_nullable_text(statement.get(), 3, new_api_key_record.key_prefix);
    bind_nullable_text(statement.get(), 4, new_api_key_record.service_name);
    if (sqlite3_bind_int(statement.get(), 5, new_api_key_record.access_level) != SQLITE_OK) {
        throw std::runtime_error("failed to bind sqlite integer parameter");
    }
    bind_nullable_text(statement.get(), 6, new_api_key_record.expires_at);
    bind_nullable_text(statement.get(), 7, new_api_key_record.note);
    step_done_or_throw(statement.get(), "failed to insert api key");

    return sqlite3_last_insert_rowid(connection.handle());
}

void RuleRepository::update_api_key(std::int64_t api_key_id,
                                    const UpdateApiKeyRecord& update_api_key_record) const {
    std::vector<std::string> assignments;
    if (update_api_key_record.service_name_is_set) {
        assignments.emplace_back("service_name = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_api_key_record.access_level.has_value()) {
        assignments.emplace_back("access_level = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_api_key_record.expires_at_is_set) {
        assignments.emplace_back("expires_at = ?" + std::to_string(assignments.size() + 1));
    }
    if (update_api_key_record.note_is_set) {
        assignments.emplace_back("note = ?" + std::to_string(assignments.size() + 1));
    }
    if (assignments.empty()) {
        throw std::runtime_error("update_api_key requires at least one changed field");
    }

    std::string sql = "UPDATE api_keys SET ";
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
    if (update_api_key_record.service_name_is_set) {
        bind_nullable_text(statement.get(), bind_index++, update_api_key_record.service_name);
    }
    if (update_api_key_record.access_level.has_value()) {
        if (sqlite3_bind_int(statement.get(), bind_index++, *update_api_key_record.access_level) != SQLITE_OK) {
            throw std::runtime_error("failed to bind sqlite integer parameter");
        }
    }
    if (update_api_key_record.expires_at_is_set) {
        bind_nullable_text(statement.get(), bind_index++, update_api_key_record.expires_at);
    }
    if (update_api_key_record.note_is_set) {
        bind_nullable_text(statement.get(), bind_index++, update_api_key_record.note);
    }
    bind_int64(statement.get(), bind_index, api_key_id);
    step_done_or_throw(statement.get(), "failed to update api key");
}

void RuleRepository::disable_api_key(std::int64_t api_key_id) const {
    static constexpr auto kSql =
        "UPDATE api_keys SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?1;";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, api_key_id);
    step_done_or_throw(statement.get(), "failed to disable api key");
}

void RuleRepository::clear_api_key_plain(std::int64_t api_key_id) const {
    static constexpr auto kSql =
        "UPDATE api_keys SET key_plain = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?1;";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, api_key_id);
    step_done_or_throw(statement.get(), "failed to clear api key plaintext");
}

void RuleRepository::delete_api_key(std::int64_t api_key_id) const {
    static constexpr auto kSql = "DELETE FROM api_keys WHERE id = ?1;";

    SqliteConnection connection(database_path_);
    Statement statement(connection.handle(), kSql);
    bind_int64(statement.get(), 1, api_key_id);
    step_done_or_throw(statement.get(), "failed to delete api key");
}

void RuleRepository::compact_api_key_ids() const {
    static constexpr auto kSelectIdsSql = "SELECT id FROM api_keys ORDER BY id ASC;";
    static constexpr auto kUpdateIdSql = "UPDATE api_keys SET id = ?1 WHERE id = ?2;";

    SqliteConnection connection(database_path_);
    auto* db = connection.handle();
    exec_sql(db, "BEGIN IMMEDIATE;", "failed to begin transaction");
    try {
        const auto ids = select_ids(db, kSelectIdsSql, "failed to load api key ids");
        for (std::size_t index = 0; index < ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            update_single_id(db, kUpdateIdSql, ids[index], temp_id, "failed to move api key id");
        }
        for (std::size_t index = 0; index < ids.size(); ++index) {
            const auto temp_id = -static_cast<std::int64_t>(index + 1);
            const auto new_id = static_cast<std::int64_t>(index + 1);
            update_single_id(db, kUpdateIdSql, temp_id, new_id, "failed to restore api key id");
        }
        exec_sql(db, "COMMIT;", "failed to commit transaction");
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        throw;
    }
}

}  // namespace roche_limit::auth_store
