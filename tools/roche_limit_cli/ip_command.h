#pragma once

#include "auth_store/rule_repository.h"

#include <string>
#include <vector>

namespace roche_limit::cli {

void handle_ip_command(const roche_limit::auth_store::RuleRepository& repository,
                       const std::vector<std::string>& args);

}  // namespace roche_limit::cli
