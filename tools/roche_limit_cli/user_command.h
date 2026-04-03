#pragma once

#include "auth_store/user_repository.h"

#include <string>
#include <vector>

namespace roche_limit::cli {

void handle_user_command(const roche_limit::auth_store::UserRepository& repository,
                         const std::vector<std::string>& args);

}  // namespace roche_limit::cli
