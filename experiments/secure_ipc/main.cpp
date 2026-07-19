/*
 * main.cpp
 *
 * Experiment 5: Secure IPC Simulation
 * Process Isolation / Secure Messaging
 *
 * Project: Post-Quantum Ready XR Native Operating System
 * Scope:   Stage 1 — C++ Benchmark Engine
 */

#include "benchmark.h"

using Clock = BenchClock;

// ============================================================================
// Configuration
// ============================================================================

static constexpr size_t PAYLOAD_SIZE       = 4 * 1024;  // 4 KB typical IPC message
static constexpr size_t WARMUP_ITERATIONS  = 100;
static constexpr size_t MEASURE_ITERATIONS = 5000;

static const char* EXPERIMENT_NAME =
    "Experiment 5: Secure IPC Simulation (ECDH+AES vs ML-KEM+AES)";

// ============================================================================
// Console Output Helpers
// ============================================================================

static void print_separator() {
    std::cout << "============================================================\n";
}

static void print_stat_line(const BenchmarkStats& s) {
    std::cout << std::fixed;
    std::cout << "  [" << s.algorithm << "] " << s.operation << "\n";
    std::cout << std::setprecision(4);
    std::cout << "    Mean       : " << s.mean_us       << " us\n";
    std::cout << "    Median     : " << s.median_us     << " us\n";
    std::cout << "    Min        : " << s.min_us        << " us\n";
    std::cout << "    Max        : " << s.max_us        << " us\n";
    std::cout << "    Std Dev    : " << s.stddev_us     << " us\n";
    std::cout << "    95% CI     : ±" << s.ci95_us      << " us\n";
    std::cout << std::setprecision(2);
    std::cout << "    Ops/sec    : " << s.ops_per_sec   << "\n";
    std::cout << std::setprecision(4);
    std::cout << "    Slowdown   : " << s.relative_slowdown << "x\n";
    std::cout << "    Overhead   : " << s.pct_overhead  << " %\n";
    std::cout << "\n";
}

// ============================================================================
// Main
// ============================================================================

int main() {
    print_separator();
    std::cout << " PQC Benchmark Suite — XenevaOS\n";
    std::cout << " " << EXPERIMENT_NAME << "\n";
    print_separator();
    std::cout << "\n";

    SystemInfo sysinfo = collect_system_info();
    std::cout << "System Information\n";
    std::cout << "  Compiler : " << sysinfo.compiler_version << "\n";
    std::cout << "  OpenSSL  : " << sysinfo.openssl_version  << "\n";
    std::cout << "  CPU      : " << sysinfo.cpu_model        << "\n";
    std::cout << "  RAM      : " << sysinfo.ram_info         << "\n";
    std::cout << "  Time     : " << sysinfo.timestamp        << "\n\n";

    std::cout << "Configuration\n";
    std::cout << "  Payload size        : " << PAYLOAD_SIZE << " bytes\n";
    std::cout << "  Warm-up iterations  : " << WARMUP_ITERATIONS << "\n";
    std::cout << "  Measured iterations : " << MEASURE_ITERATIONS << "\n\n";

    auto suite_start = Clock::now();
    long mem_before = get_peak_rss_kb();

    std::vector<BenchmarkStats> all_results;

    print_separator();
    std::cout << " Running Secure IPC Benchmark (Full Roundtrip)\n";
    print_separator();
    std::cout << "\n";

    std::cout << "[RUN] Classical IPC (ECDH P-256 + AES-256-GCM)...\n";
    auto class_times = bench_classical_ipc(PAYLOAD_SIZE, WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto class_stats = compute_stats("Classical (ECDH+AES)", "IPC Roundtrip", class_times, MEASURE_ITERATIONS);

    std::cout << "[RUN] Post-Quantum IPC (ML-KEM-768 + AES-256-GCM)...\n";
    auto pq_times = bench_pq_ipc(PAYLOAD_SIZE, WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto pq_stats = compute_stats("PQ (ML-KEM+AES)", "IPC Roundtrip", pq_times, MEASURE_ITERATIONS);

    compute_relative(class_stats, pq_stats);

    print_stat_line(class_stats);
    print_stat_line(pq_stats);

    all_results.push_back(class_stats);
    all_results.push_back(pq_stats);

    long mem_after = get_peak_rss_kb();
    auto suite_end = Clock::now();
    double elapsed = std::chrono::duration<double>(suite_end - suite_start).count();

    std::cout << "Memory Usage\n";
    std::cout << "  Delta : " << (mem_after - mem_before) << " KB\n\n";
    std::cout << "Total benchmark time: " << std::fixed << std::setprecision(2) << elapsed << " seconds\n\n";

    // Write from current directory (we will ensure the script is run from project root)
    std::string results_dir = "results";
    write_csv(results_dir + "/secure_ipc_results.csv", all_results, sysinfo);
    write_json(results_dir + "/secure_ipc_results.json", all_results, sysinfo, EXPERIMENT_NAME);
    write_log(results_dir + "/secure_ipc_benchmark.log", all_results, sysinfo, EXPERIMENT_NAME, elapsed);

    std::cout << "\n";
    print_separator();
    std::cout << " Experiment 5 Complete\n";
    print_separator();

    return 0;
}
