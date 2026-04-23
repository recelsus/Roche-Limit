#include "auth_store/rule_repository.h"

#include "auth_store/sqlite_connection.h"
#include "sqlite_statement.h"

#include <sqlite3.h>

namespace roche_limit::auth_store {

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
