#pragma once

#include <string>
#include <string_view>

namespace roche_limit::common {

std::string sha256_hex(std::string_view input);

}  // namespace roche_limit::common
