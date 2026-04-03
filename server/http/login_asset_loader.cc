#include "login_asset_loader.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace roche_limit::server::http {

namespace {

std::filesystem::path source_root() {
#ifdef ROCHE_LIMIT_SOURCE_DIR
    return std::filesystem::path(ROCHE_LIMIT_SOURCE_DIR);
#else
    return std::filesystem::current_path();
#endif
}

std::filesystem::path executable_directory() {
    return std::filesystem::current_path();
}

std::vector<std::filesystem::path> candidate_paths(std::string_view asset_name) {
    const auto executable_dir = executable_directory();
    return {
        executable_dir / "assets" / std::string(asset_name),
        executable_dir.parent_path() / "assets" / std::string(asset_name),
        std::filesystem::current_path() / "server" / "assets" / std::string(asset_name),
        source_root() / "server" / "assets" / std::string(asset_name),
    };
}

}  // namespace

std::string load_login_asset(std::string_view asset_name) {
    for (const auto& path : candidate_paths(asset_name)) {
        if (!std::filesystem::exists(path)) {
            continue;
        }

        std::ifstream input(path);
        if (!input.is_open()) {
            continue;
        }

        std::ostringstream buffer;
        buffer << input.rdbuf();
        const auto content = buffer.str();
        if (!content.empty()) {
            return content;
        }
    }

    throw std::runtime_error("failed to load login asset: " + std::string(asset_name));
}

}  // namespace roche_limit::server::http
