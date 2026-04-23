#include "crash_handler.h"

#include <csignal>
#include <cstdlib>
#include <execinfo.h>
#include <unistd.h>

namespace roche_limit::server {

namespace {

void crash_signal_handler(int signal_number) {
  constexpr int kMaxFrames = 64;
  void *frames[kMaxFrames]{};
  const int frame_count = backtrace(frames, kMaxFrames);

  static constexpr char kSegvMessage[] = "roche-limit fatal signal SIGSEGV\n";
  static constexpr char kAbrtMessage[] = "roche-limit fatal signal SIGABRT\n";
  static constexpr char kBusMessage[] = "roche-limit fatal signal SIGBUS\n";
  static constexpr char kIllMessage[] = "roche-limit fatal signal SIGILL\n";
  static constexpr char kFpeMessage[] = "roche-limit fatal signal SIGFPE\n";
  static constexpr char kUnknownMessage[] =
      "roche-limit fatal signal unknown\n";

  const char *message = kUnknownMessage;
  std::size_t message_length = sizeof(kUnknownMessage) - 1;

  switch (signal_number) {
  case SIGSEGV:
    message = kSegvMessage;
    message_length = sizeof(kSegvMessage) - 1;
    break;
  case SIGABRT:
    message = kAbrtMessage;
    message_length = sizeof(kAbrtMessage) - 1;
    break;
  case SIGBUS:
    message = kBusMessage;
    message_length = sizeof(kBusMessage) - 1;
    break;
  case SIGILL:
    message = kIllMessage;
    message_length = sizeof(kIllMessage) - 1;
    break;
  case SIGFPE:
    message = kFpeMessage;
    message_length = sizeof(kFpeMessage) - 1;
    break;
  default:
    break;
  }

  write(STDERR_FILENO, message, message_length);
  backtrace_symbols_fd(frames, frame_count, STDERR_FILENO);
  _Exit(128 + signal_number);
}

} // namespace

void install_crash_handler() {
  std::signal(SIGSEGV, crash_signal_handler);
  std::signal(SIGABRT, crash_signal_handler);
  std::signal(SIGBUS, crash_signal_handler);
  std::signal(SIGILL, crash_signal_handler);
  std::signal(SIGFPE, crash_signal_handler);
}

} // namespace roche_limit::server
