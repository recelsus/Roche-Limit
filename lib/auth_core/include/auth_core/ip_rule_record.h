#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace roche_limit::auth_core {

enum class IpRuleEffect {
    Allow,
    Deny,
};

enum class AddressFamily {
    IPv4,
    IPv6,
};

enum class IpRuleType {
    Single,
    Cidr,
};

struct IpRuleRecord {
    std::int64_t id;
    std::string value_text;
    AddressFamily address_family;
    IpRuleType rule_type;
    std::optional<int> prefix_length;
    IpRuleEffect effect;
    bool enabled;
    std::optional<std::string> note;
    std::string created_at;
    std::string updated_at;
};

struct IpServiceLevelRecord {
    std::int64_t id;
    std::int64_t ip_rule_id;
    std::string service_name;
    int access_level;
    bool enabled;
    std::optional<std::string> note;
    std::string created_at;
    std::string updated_at;
};

}  // namespace roche_limit::auth_core
