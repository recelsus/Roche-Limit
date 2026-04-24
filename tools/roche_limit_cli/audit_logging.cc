#include "audit_logging.h"

#include <sstream>

namespace roche_limit::cli {

namespace {

std::string escape_json_string(std::string_view value) {
  std::ostringstream stream;
  for (const char ch : value) {
    switch (ch) {
    case '\\':
      stream << "\\\\";
      break;
    case '"':
      stream << "\\\"";
      break;
    case '\b':
      stream << "\\b";
      break;
    case '\f':
      stream << "\\f";
      break;
    case '\n':
      stream << "\\n";
      break;
    case '\r':
      stream << "\\r";
      break;
    case '\t':
      stream << "\\t";
      break;
    default:
      if (static_cast<unsigned char>(ch) < 0x20) {
        stream << "\\u00";
        static constexpr char kHex[] = "0123456789abcdef";
        stream << kHex[(ch >> 4) & 0x0f] << kHex[ch & 0x0f];
      } else {
        stream << ch;
      }
      break;
    }
  }
  return stream.str();
}

std::string command_metadata_json(const std::vector<std::string> &args,
                                  std::optional<std::string> details_json) {
  std::ostringstream stream;
  stream << "{\"command\":\"" << escape_json_string(sanitize_cli_arguments(args))
         << "\"";
  if (details_json.has_value()) {
    stream << ",\"details\":" << *details_json;
  }
  stream << '}';
  return stream.str();
}

} // namespace

std::string sanitize_cli_arguments(const std::vector<std::string> &args) {
  auto sanitized = args;
  if (sanitized.size() >= 4 && sanitized[1] == "key" &&
      sanitized[2] == "add") {
    sanitized[3] = "[REDACTED_API_KEY]";
  }
  for (std::size_t index = 0; index + 1 < sanitized.size(); ++index) {
    if (sanitized[index] == "--password") {
      sanitized[index + 1] = "[REDACTED_PASSWORD]";
    }
  }

  std::ostringstream stream;
  for (std::size_t index = 0; index < sanitized.size(); ++index) {
    if (index > 0) {
      stream << ' ';
    }
    stream << sanitized[index];
  }
  return stream.str();
}

void audit_cli_success(
    const roche_limit::auth_store::AuditRepository &audit_repository,
    std::string_view event_type, std::optional<std::string> target_type,
    std::optional<std::string> target_id, const std::vector<std::string> &args,
    std::optional<std::string> details_json) {
  audit_repository.insert_event(roche_limit::auth_store::NewAuditEvent{
      .event_type = std::string(event_type),
      .actor_type = "cli",
      .target_type = std::move(target_type),
      .target_id = std::move(target_id),
      .result = "success",
      .metadata_json = command_metadata_json(args, std::move(details_json)),
  });
}

void audit_cli_error(
    const roche_limit::auth_store::AuditRepository &audit_repository,
    const std::vector<std::string> &args, std::string_view stage) {
  audit_repository.insert_event(roche_limit::auth_store::NewAuditEvent{
      .event_type = "cli_error",
      .actor_type = "cli",
      .result = "error",
      .reason = std::string(stage),
      .metadata_json = command_metadata_json(
          args, std::string("{\"stage\":\"") + std::string(stage) + "\"}"),
  });
}

} // namespace roche_limit::cli
