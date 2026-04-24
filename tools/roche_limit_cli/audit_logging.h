#pragma once

#include "auth_store/audit_repository.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace roche_limit::cli {

std::string sanitize_cli_arguments(const std::vector<std::string> &args);

void audit_cli_success(
    const roche_limit::auth_store::AuditRepository &audit_repository,
    std::string_view event_type, std::optional<std::string> target_type,
    std::optional<std::string> target_id, const std::vector<std::string> &args,
    std::optional<std::string> details_json = std::nullopt);

void audit_cli_error(
    const roche_limit::auth_store::AuditRepository &audit_repository,
    const std::vector<std::string> &args, std::string_view stage);

} // namespace roche_limit::cli
