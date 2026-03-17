#include "app_config.h"

namespace roche_limit::server::config {

AppConfig load_app_config(const std::filesystem::path& database_path) {
    return AppConfig{
        .listen_address = "0.0.0.0",
        .port = 8080,
        .database_path = database_path,
    };
}

}  // namespace roche_limit::server::config
