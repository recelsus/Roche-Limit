#include "request_observability.h"

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <tuple>

namespace roche_limit::server::http {

namespace {

using MetricKey = std::tuple<std::string, std::string, std::string>;

std::atomic<std::uint64_t> g_next_request_id{1};
std::mutex g_metrics_mutex;
std::map<MetricKey, std::uint64_t> g_auth_request_counts;

std::string escape_label(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (char ch : value) {
        if (ch == '\\' || ch == '"') {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

}  // namespace

std::string next_request_id() {
    return "rl-" + std::to_string(g_next_request_id.fetch_add(1, std::memory_order_relaxed));
}

void record_auth_request(std::string_view endpoint,
                         std::string_view result,
                         std::string_view reason) {
    std::lock_guard lock(g_metrics_mutex);
    ++g_auth_request_counts[MetricKey(std::string(endpoint), std::string(result), std::string(reason))];
}

std::string prometheus_metrics_text() {
    std::lock_guard lock(g_metrics_mutex);

    std::ostringstream output;
    output << "# HELP roche_limit_auth_requests_total Number of auth-related requests by endpoint, result, and reason.\n";
    output << "# TYPE roche_limit_auth_requests_total counter\n";
    for (const auto& [key, count] : g_auth_request_counts) {
        const auto& [endpoint, result, reason] = key;
        output << "roche_limit_auth_requests_total{endpoint=\""
               << escape_label(endpoint) << "\",result=\""
               << escape_label(result) << "\",reason=\""
               << escape_label(reason) << "\"} " << count << '\n';
    }

    output << "# HELP roche_limit_request_ids_issued_total Number of request ids issued by this process.\n";
    output << "# TYPE roche_limit_request_ids_issued_total counter\n";
    output << "roche_limit_request_ids_issued_total "
           << (g_next_request_id.load(std::memory_order_relaxed) - 1) << '\n';
    return output.str();
}

}  // namespace roche_limit::server::http
