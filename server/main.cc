#include <drogon/drogon.h>

#include <iostream>
#include <memory>

#include "auth_core/auth_service.h"
#include "auth_store/rule_repository.h"
#include "auth_store/schema_bootstrap.h"
#include "common/debug_log.h"
#include "config/app_config.h"
#include "http/auth_controller.h"
#include "http/root_controller.h"

int main(int argc, char* argv[]) {
    using namespace drogon;

    const auto executable_path = argc > 0 ? std::filesystem::path(argv[0]) : std::filesystem::path{};
    const auto bootstrap_result = roche_limit::auth_store::bootstrap_sqlite_schema(executable_path);
    const auto config = roche_limit::server::config::load_app_config(bootstrap_result.database_path);
    auto repository = std::make_shared<roche_limit::auth_store::RuleRepository>(config.database_path);
    auto auth_service = std::make_shared<roche_limit::auth_core::AuthService>(*repository);
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cout << "Repository address: " << static_cast<const void*>(repository.get()) << std::endl;
        std::cout << "AuthService repository address: "
                  << static_cast<const void*>(auth_service->repository_address()) << std::endl;
    }

    roche_limit::server::http::register_root_routes();
    roche_limit::server::http::register_auth_routes(auth_service);

    std::cout << "Using sqlite database at " << bootstrap_result.database_path << std::endl;
    std::cout << "Starting roche-limit on port " << config.port << std::endl;
    app().addListener(config.listen_address, config.port).run();
    return 0;
}
