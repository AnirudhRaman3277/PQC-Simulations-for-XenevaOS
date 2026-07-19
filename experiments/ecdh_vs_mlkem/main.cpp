/*
 * main.cpp
 *
 * Experiment 1: ECDH P-256 vs ML-KEM-768
 * Kernel Crypto Framework / Secure Session Establishment
 *
 * Driver program that executes all benchmarks for Experiment 1,
 * computes statistics, and writes results to CSV, JSON, and log files.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 * Scope:   Stage 1 — C++ Benchmark Engine
 */

#include "benchmark.h"

// ============================================================================
// Configuration
// ============================================================================

static constexpr size_t WARMUP_ITERATIONS  = 100;
static constexpr size_t MEASURE_ITERATIONS = 5000;

static const char* EXPERIMENT_NAME =
    "Experiment 1: ECDH P-256 vs ML-KEM-768 — Secure Session Establishment";

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

    // Collect system information
    SystemInfo sysinfo = collect_system_info();
    std::cout << "System Information\n";
    std::cout << "  Compiler : " << sysinfo.compiler_version << "\n";
    std::cout << "  OpenSSL  : " << sysinfo.openssl_version  << "\n";
    std::cout << "  CPU      : " << sysinfo.cpu_model        << "\n";
    std::cout << "  Kernel   : " << sysinfo.kernel_version   << "\n";
    std::cout << "  RAM      : " << sysinfo.ram_info         << "\n";
    std::cout << "  Time     : " << sysinfo.timestamp        << "\n";
    std::cout << "\n";

    std::cout << "Configuration\n";
    std::cout << "  Warm-up iterations  : " << WARMUP_ITERATIONS  << "\n";
    std::cout << "  Measured iterations : " << MEASURE_ITERATIONS << "\n";
    std::cout << "\n";

    // Record start time
    auto suite_start = BenchClock::now();

    // Record initial memory
    long mem_before = get_peak_rss_kb();

    // Storage for all results
    std::vector<BenchmarkStats> all_results;

    // ------------------------------------------------------------------
    // ECDH P-256
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " ECDH P-256 Benchmarks\n";
    print_separator();
    std::cout << "\n";

    // Keygen
    std::cout << "[RUN] ECDH P-256 Key Generation (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto ecdh_keygen_times = bench_ecdh_keygen(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto ecdh_keygen_stats = compute_stats("ECDH-P256", "Key Generation",
                                           ecdh_keygen_times, MEASURE_ITERATIONS);
    print_stat_line(ecdh_keygen_stats);
    all_results.push_back(ecdh_keygen_stats);

    // Shared Secret
    std::cout << "[RUN] ECDH P-256 Shared Secret Derivation (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto ecdh_ss_times = bench_ecdh_shared_secret(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto ecdh_ss_stats = compute_stats("ECDH-P256", "Shared Secret",
                                       ecdh_ss_times, MEASURE_ITERATIONS);
    print_stat_line(ecdh_ss_stats);
    all_results.push_back(ecdh_ss_stats);

    // Full Key Exchange
    std::cout << "[RUN] ECDH P-256 Full Key Exchange (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto ecdh_kx_times = bench_ecdh_key_exchange(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto ecdh_kx_stats = compute_stats("ECDH-P256", "Full Key Exchange",
                                       ecdh_kx_times, MEASURE_ITERATIONS);
    print_stat_line(ecdh_kx_stats);
    all_results.push_back(ecdh_kx_stats);

    // ------------------------------------------------------------------
    // ML-KEM-768
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " ML-KEM-768 Benchmarks\n";
    print_separator();
    std::cout << "\n";

    // Keygen
    std::cout << "[RUN] ML-KEM-768 Key Generation (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto mlkem_keygen_times = bench_mlkem_keygen(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto mlkem_keygen_stats = compute_stats("ML-KEM-768", "Key Generation",
                                            mlkem_keygen_times, MEASURE_ITERATIONS);
    print_stat_line(mlkem_keygen_stats);
    all_results.push_back(mlkem_keygen_stats);

    // Encapsulation
    std::cout << "[RUN] ML-KEM-768 Encapsulation (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto mlkem_encaps_times = bench_mlkem_encaps(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto mlkem_encaps_stats = compute_stats("ML-KEM-768", "Encapsulation",
                                            mlkem_encaps_times, MEASURE_ITERATIONS);
    print_stat_line(mlkem_encaps_stats);
    all_results.push_back(mlkem_encaps_stats);

    // Decapsulation
    std::cout << "[RUN] ML-KEM-768 Decapsulation (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto mlkem_decaps_times = bench_mlkem_decaps(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto mlkem_decaps_stats = compute_stats("ML-KEM-768", "Decapsulation",
                                            mlkem_decaps_times, MEASURE_ITERATIONS);
    print_stat_line(mlkem_decaps_stats);
    all_results.push_back(mlkem_decaps_stats);

    // Full Key Exchange
    std::cout << "[RUN] ML-KEM-768 Full Key Exchange (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto mlkem_kx_times = bench_mlkem_key_exchange(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto mlkem_kx_stats = compute_stats("ML-KEM-768", "Full Key Exchange",
                                        mlkem_kx_times, MEASURE_ITERATIONS);
    print_stat_line(mlkem_kx_stats);
    all_results.push_back(mlkem_kx_stats);

    // ------------------------------------------------------------------
    // Relative comparisons
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " Relative Comparisons\n";
    print_separator();
    std::cout << "\n";

    // Keygen: ECDH vs ML-KEM
    compute_relative(all_results[0], all_results[3]);
    std::cout << "  Key Generation:\n";
    std::cout << "    ML-KEM-768 vs ECDH-P256 : "
              << std::fixed << std::setprecision(4)
              << all_results[3].relative_slowdown << "x  ("
              << all_results[3].pct_overhead << "% overhead)\n\n";

    // Full Key Exchange: ECDH vs ML-KEM
    compute_relative(all_results[2], all_results[6]);
    std::cout << "  Full Key Exchange:\n";
    std::cout << "    ML-KEM-768 vs ECDH-P256 : "
              << all_results[6].relative_slowdown << "x  ("
              << all_results[6].pct_overhead << "% overhead)\n\n";

    // ------------------------------------------------------------------
    // Memory usage
    // ------------------------------------------------------------------
    long mem_after = get_peak_rss_kb();
    std::cout << "Memory Usage\n";
    if (mem_before >= 0 && mem_after >= 0) {
        std::cout << "  Peak RSS (before) : " << mem_before << " KB\n";
        std::cout << "  Peak RSS (after)  : " << mem_after  << " KB\n";
        std::cout << "  Delta             : " << (mem_after - mem_before) << " KB\n";
    } else {
        std::cout << "  (unable to measure)\n";
    }
    std::cout << "\n";

    // ------------------------------------------------------------------
    // Total elapsed time
    // ------------------------------------------------------------------
    auto suite_end = BenchClock::now();
    double total_elapsed_sec =
        std::chrono::duration<double>(suite_end - suite_start).count();

    std::cout << "Total benchmark time: "
              << std::fixed << std::setprecision(2)
              << total_elapsed_sec << " seconds\n\n";

    // ------------------------------------------------------------------
    // Write output files
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " Writing Results\n";
    print_separator();
    std::cout << "\n";

    // Determine output directory relative to the executable
    // We write into the project's results/ directory
    std::string results_dir = "results";

    write_csv(results_dir + "/ecdh_vs_mlkem_results.csv", all_results, sysinfo);
    write_json(results_dir + "/ecdh_vs_mlkem_results.json", all_results,
               sysinfo, EXPERIMENT_NAME);
    write_log(results_dir + "/ecdh_vs_mlkem_benchmark.log", all_results,
              sysinfo, EXPERIMENT_NAME, total_elapsed_sec);

    std::cout << "\n";
    print_separator();
    std::cout << " Experiment 1 Complete\n";
    print_separator();

    return 0;
}
