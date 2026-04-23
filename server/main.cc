#include <drogon/drogon.h>

#include <iostream>
#include <memory>

#include "auth_core/auth_service.h"
#include "auth_core/login_service.h"
#include "auth_store/rule_repository.h"
#include "auth_store/schema_bootstrap.h"
#include "auth_store/user_repository.h"
#include "common/debug_log.h"
#include "config/app_config.h"
#include "http/auth_controller.h"
#include "http/login_controller.h"
#include "http/metrics_controller.h"
#include "http/root_controller.h"

int main(int argc, char* argv[]) {
    using namespace drogon;

    const auto executable_path = argc > 0 ? std::filesystem::path(argv[0]) : std::filesystem::path{};
    const auto bootstrap_result = roche_limit::auth_store::bootstrap_sqlite_schema(executable_path);
    const auto config = roche_limit::server::config::load_app_config(bootstrap_result.database_path);
    auto repository = std::make_shared<roche_limit::auth_store::RuleRepository>(config.database_path);
    auto user_repository = std::make_shared<roche_limit::auth_store::UserRepository>(config.database_path);
    auto auth_service = std::make_shared<roche_limit::auth_core::AuthService>(*repository);
    auto login_service =
        std::make_shared<roche_limit::auth_core::LoginService>(*repository, *user_repository);
    std::cout << "Verbose logging: "
              << (roche_limit::common::verbose_logging_enabled() ? "enabled" : "disabled")
              << std::endl;
    if (roche_limit::common::verbose_logging_enabled()) {
        std::cout << "Repository address: " << static_cast<const void*>(repository.get()) << std::endl;
        std::cout << "AuthService repository address: "
                  << static_cast<const void*>(auth_service->repository_address()) << std::endl;
    }

    roche_limit::server::http::register_root_routes();
    roche_limit::server::http::register_auth_routes(auth_service);
    roche_limit::server::http::register_login_routes(login_service);
    roche_limit::server::http::register_metrics_routes();

    std::cout << "Using sqlite database at " << config.database_path << std::endl;
    std::cout << "Starting roche-limit on port " << config.port << std::endl;
    app().addListener(config.listen_address, config.port).run();
    return 0;
}
