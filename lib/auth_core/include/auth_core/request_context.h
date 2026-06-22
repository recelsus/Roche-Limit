#pragma once

#include <optional>
#include <string>

namespace roche_limit::auth_core {

struct ClientCertContext {
    std::string verify;
    std::optional<std::string> fingerprint_sha256;
    std::optional<std::string> serial_number;
    std::optional<std::string> subject_dn;
    std::optional<std::string> issuer_dn;
    bool fingerprint_valid{true};
};

struct RequestContext {
    std::string client_ip;
    std::string service_name;
    bool service_name_valid{true};
    std::optional<std::string> api_key;
    std::optional<int> required_access_level;
    bool required_access_level_present{false};
    bool required_access_level_valid{true};
    int default_access_level{0};
    bool default_access_level_present{false};
    bool default_access_level_valid{true};
    std::optional<ClientCertContext> client_cert;
};

}  // namespace roche_limit::auth_core
