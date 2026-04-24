#pragma once

#include "auth_store/audit_repository.h"

#include <string>
#include <vector>

namespace roche_limit::cli {

void handle_audit_command(
    const roche_limit::auth_store::AuditRepository &audit_repository,
    const std::vector<std::string> &args);

} // namespace roche_limit::cli
