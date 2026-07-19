/*
 * main.cpp
 *
 * Experiment 4: Package Verification
 * Package Manager / Software Supply Chain Security
 *
 * Simulates a system update involving 100, 500, or 1000 packages.
 * Evaluates the total latency and throughput of validating large 
 * batches of packages using classical and post-quantum signatures.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 * Scope:   Stage 1 — C++ Benchmark Engine
 */

#include "benchmark.h"

using Clock = BenchClock;

// ============================================================================
// Configuration
// ============================================================================

static constexpr size_t PKG_SIZE           = 1 * 1024 * 1024;  // 1 MB
static constexpr size_t WARMUP_ITERATIONS  = 2;
static constexpr size_t MEASURE_ITERATIONS = 10;

static const std::vector<size_t> BATCH_SIZES = {100, 500, 1000};

static const char* EXPERIMENT_NAME =
    "Experiment 4: Package Verification — Software Supply Chain";

// ============================================================================
// Console Output Helpers
// ============================================================================

static void print_separator() {
    std::cout << "============================================================\n";
}

static void print_stat_line(const BenchmarkStats& s, size_t batch_size) {
    std::cout << std::fixed;
    std::cout << "  [" << s.algorithm << "] " << s.operation << "\n";
    std::cout << std::setprecision(4);
    std::cout << "    Mean       : " << s.mean_us / 1000.0   << " ms\n";
    std::cout << "    Median     : " << s.median_us / 1000.0 << " ms\n";
    std::cout << "    Min        : " << s.min_us / 1000.0    << " ms\n";
    std::cout << "    Max        : " << s.max_us / 1000.0    << " ms\n";
    std::cout << "    Std Dev    : " << s.stddev_us / 1000.0 << " ms\n";
    std::cout << "    95% CI     : ±" << s.ci95_us / 1000.0  << " ms\n";
    std::cout << std::setprecision(2);
    // Ops/sec is batches/sec. Multiply by batch_size to get packages/sec.
    std::cout << "    Throughput : " << (s.ops_per_sec * batch_size) << " packages/sec\n";
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
    std::cout << "  Package size        : " << PKG_SIZE / (1024 * 1024) << " MB\n";
    std::cout << "  Warm-up iterations  : " << WARMUP_ITERATIONS << "\n";
    std::cout << "  Measured iterations : " << MEASURE_ITERATIONS << "\n\n";

    std::vector<unsigned char> package(PKG_SIZE);
    RAND_bytes(package.data(), static_cast<int>(PKG_SIZE));
    std::cout << "  Generated " << PKG_SIZE / (1024 * 1024) << " MB synthetic package.\n\n";

    auto suite_start = Clock::now();
    long mem_before = get_peak_rss_kb();

    std::vector<BenchmarkStats> all_results;

    for (size_t batch : BATCH_SIZES) {
        print_separator();
        std::cout << " Batch Size: " << batch << " Packages\n";
        print_separator();
        std::cout << "\n";
        
        std::string op_name = "Verify " + std::to_string(batch) + " Packages";

        // RSA-2048
        std::cout << "[RUN] RSA-2048 Verification (" << batch << " pkgs/batch)...\n";
        auto rsa_times = bench_rsa_package_batch(
            package.data(), PKG_SIZE, batch, WARMUP_ITERATIONS, MEASURE_ITERATIONS);
        auto rsa_stats = compute_stats("RSA-2048", op_name, rsa_times, MEASURE_ITERATIONS);
        
        // ML-DSA-65
        std::cout << "[RUN] ML-DSA-65 Verification (" << batch << " pkgs/batch)...\n";
        auto mldsa_times = bench_mldsa_package_batch(
            package.data(), PKG_SIZE, batch, WARMUP_ITERATIONS, MEASURE_ITERATIONS);
        auto mldsa_stats = compute_stats("ML-DSA-65", op_name, mldsa_times, MEASURE_ITERATIONS);

        // Compute relative differences
        compute_relative(rsa_stats, mldsa_stats);
        
        print_stat_line(rsa_stats, batch);
        print_stat_line(mldsa_stats, batch);

        all_results.push_back(rsa_stats);
        all_results.push_back(mldsa_stats);
    }

    long mem_after = get_peak_rss_kb();
    auto suite_end = Clock::now();
    double elapsed = std::chrono::duration<double>(suite_end - suite_start).count();

    std::cout << "Memory Usage\n";
    std::cout << "  Delta : " << (mem_after - mem_before) << " KB\n\n";
    std::cout << "Total benchmark time: " << std::fixed << std::setprecision(2) << elapsed << " seconds\n\n";

    std::string results_dir = "results";
    write_csv(results_dir + "/package_verify_results.csv", all_results, sysinfo);
    write_json(results_dir + "/package_verify_results.json", all_results, sysinfo, EXPERIMENT_NAME);
    write_log(results_dir + "/package_verify_benchmark.log", all_results, sysinfo, EXPERIMENT_NAME, elapsed);

    std::cout << "\n";
    print_separator();
    std::cout << " Experiment 4 Complete\n";
    print_separator();

    return 0;
}
