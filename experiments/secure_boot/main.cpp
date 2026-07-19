/*
 * main.cpp
 *
 * Experiment 3: Secure Boot Simulation
 * Trusted Boot / Kernel Integrity
 *
 * Simulates the XenevaOS secure boot pipeline:
 *   - Creates a synthetic 4 MB kernel image
 *   - Signs it with RSA-2048 (classical) and ML-DSA-65 (post-quantum)
 *   - Benchmarks verification latency over 1000 simulated boots
 *
 * Project: Post-Quantum Ready XR Native Operating System
 * Scope:   Stage 1 — C++ Benchmark Engine
 */

#include "benchmark.h"

// ============================================================================
// Configuration
// ============================================================================

static constexpr size_t KERNEL_SIZE        = 4 * 1024 * 1024;  // 4 MB
static constexpr size_t WARMUP_ITERATIONS  = 100;
static constexpr size_t VERIFY_ITERATIONS  = 1000;

static const char* EXPERIMENT_NAME =
    "Experiment 3: Secure Boot Simulation — Trusted Boot / Kernel Integrity";

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
// Extended JSON Output (includes boot simulation metadata)
// ============================================================================

static void write_boot_json(const std::string& filepath,
                            const std::vector<BenchmarkStats>& results,
                            const SystemInfo& sysinfo,
                            const std::string& experiment_name,
                            size_t kernel_size_bytes,
                            double rsa_sign_time_us,
                            double mldsa_sign_time_us) {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Cannot open JSON file: " << filepath << "\n";
        return;
    }

    ofs << std::fixed;
    ofs << "{\n";
    ofs << "  \"experiment\": \"" << json_escape(experiment_name) << "\",\n";

    // System info
    ofs << "  \"system\": {\n";
    ofs << "    \"compiler\": \""   << json_escape(sysinfo.compiler) << "\",\n";
    ofs << "    \"compiler_version\": \""   << json_escape(sysinfo.compiler_version) << "\",\n";
    ofs << "    \"optimization_flags\": \""   << json_escape(sysinfo.optimization_flags) << "\",\n";
    ofs << "    \"openssl\": \""    << json_escape(sysinfo.openssl_version)  << "\",\n";
    ofs << "    \"cpu_vendor\": \"" << json_escape(sysinfo.cpu_vendor) << "\",\n";
    ofs << "    \"cpu_model\": \""  << json_escape(sysinfo.cpu_model)        << "\",\n";
    ofs << "    \"cpu_arch\": \""   << json_escape(sysinfo.cpu_arch) << "\",\n";
    ofs << "    \"logical_cores\": \"" << json_escape(sysinfo.logical_cores) << "\",\n";
    ofs << "    \"physical_cores\": \"" << json_escape(sysinfo.physical_cores) << "\",\n";
    ofs << "    \"os_name\": \""    << json_escape(sysinfo.os_name)   << "\",\n";
    ofs << "    \"kernel\": \""     << json_escape(sysinfo.kernel_version)   << "\",\n";
    ofs << "    \"ram\": \""        << json_escape(sysinfo.ram_info)         << "\",\n";
    ofs << "    \"timestamp\": \""  << json_escape(sysinfo.timestamp)        << "\"\n";
    ofs << "  },\n";

    // Boot simulation parameters
    ofs << "  \"boot_simulation\": {\n";
    ofs << "    \"kernel_size_bytes\": " << kernel_size_bytes << ",\n";
    ofs << "    \"kernel_size_mb\": " << std::setprecision(1)
        << static_cast<double>(kernel_size_bytes) / (1024.0 * 1024.0) << ",\n";
    ofs << std::setprecision(4);
    ofs << "    \"rsa_sign_time_us\": "   << rsa_sign_time_us   << ",\n";
    ofs << "    \"mldsa_sign_time_us\": " << mldsa_sign_time_us << "\n";
    ofs << "  },\n";

    // Timing results (verification only)
    ofs << "  \"results\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        ofs << "    {\n";
        ofs << "      \"algorithm\": \""   << json_escape(r.algorithm)  << "\",\n";
        ofs << "      \"compiler\": \""    << json_escape(sysinfo.compiler) << "\",\n";
        ofs << "      \"compiler_version\": \"" << json_escape(sysinfo.compiler_version) << "\",\n";
        ofs << "      \"optimization_flags\": \"" << json_escape(sysinfo.optimization_flags) << "\",\n";
        ofs << "      \"cpu_model\": \""   << json_escape(sysinfo.cpu_model) << "\",\n";
        ofs << "      \"operating_system\": \"" << json_escape(sysinfo.os_name) << "\",\n";
        ofs << "      \"timestamp\": \""   << json_escape(sysinfo.timestamp) << "\",\n";
        ofs << "      \"operation\": \""   << json_escape(r.operation)  << "\",\n";
        ofs << "      \"iterations\": "    << r.iterations              << ",\n";
        ofs << std::setprecision(4);
        ofs << "      \"average\": "       << r.mean_us                << ",\n";
        ofs << "      \"median\": "        << r.median_us              << ",\n";
        ofs << "      \"minimum\": "       << r.min_us                 << ",\n";
        ofs << "      \"maximum\": "       << r.max_us                 << ",\n";
        ofs << "      \"variance\": "      << r.variance_us            << ",\n";
        ofs << "      \"standard_deviation\": " << r.stddev_us         << ",\n";
        ofs << "      \"ci95_us\": "       << r.ci95_us                << ",\n";
        ofs << std::setprecision(2);
        ofs << "      \"ops_per_sec\": "   << r.ops_per_sec            << ",\n";
        ofs << std::setprecision(4);
        ofs << "      \"relative_slowdown\": " << r.relative_slowdown  << ",\n";
        ofs << "      \"overhead_pct\": "  << r.pct_overhead           << "\n";
        ofs << "    }";
        if (i + 1 < results.size()) ofs << ",";
        ofs << "\n";
    }
    ofs << "  ]\n";
    ofs << "}\n";

    ofs.close();
    std::cout << "[OK] JSON written: " << filepath << "\n";
}

// ============================================================================
// Extended Log Output (includes boot simulation metadata)
// ============================================================================

static void write_boot_log(const std::string& filepath,
                           const std::vector<BenchmarkStats>& results,
                           const SystemInfo& sysinfo,
                           const std::string& experiment_name,
                           double total_elapsed_sec,
                           size_t kernel_size_bytes,
                           double rsa_sign_time_us,
                           double mldsa_sign_time_us) {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Cannot open log file: " << filepath << "\n";
        return;
    }

    ofs << "========================================\n";
    ofs << " Benchmark Log\n";
    ofs << " " << experiment_name << "\n";
    ofs << "========================================\n\n";

    ofs << "System Information\n";
    ofs << "  Compiler : " << sysinfo.compiler_version << "\n";
    ofs << "  OpenSSL  : " << sysinfo.openssl_version  << "\n";
    ofs << "  CPU      : " << sysinfo.cpu_model        << "\n";
    ofs << "  Kernel   : " << sysinfo.kernel_version   << "\n";
    ofs << "  RAM      : " << sysinfo.ram_info         << "\n";
    ofs << "  Time     : " << sysinfo.timestamp        << "\n";
    ofs << "  Duration : " << std::fixed << std::setprecision(2)
        << total_elapsed_sec << " seconds\n\n";

    ofs << "----------------------------------------\n";
    ofs << " Simulation Parameters\n";
    ofs << "----------------------------------------\n\n";

    ofs << "  Kernel image size : " << kernel_size_bytes / (1024 * 1024) << " MB ("
        << kernel_size_bytes << " bytes)\n";
    ofs << "  Warmup            : " << WARMUP_ITERATIONS << " verifications\n";
    ofs << "  Measured          : " << VERIFY_ITERATIONS << " verifications\n\n";

    ofs << "----------------------------------------\n";
    ofs << " Signing (Build-Time Cost)\n";
    ofs << "----------------------------------------\n\n";

    ofs << std::setprecision(4);
    ofs << "  RSA-2048    : " << rsa_sign_time_us   << " us ("
        << std::setprecision(2) << rsa_sign_time_us / 1000.0 << " ms)\n";
    ofs << std::setprecision(4);
    ofs << "  ML-DSA-65   : " << mldsa_sign_time_us << " us ("
        << std::setprecision(2) << mldsa_sign_time_us / 1000.0 << " ms)\n\n";

    ofs << "----------------------------------------\n";
    ofs << " Verification Results (Boot-Time Cost)\n";
    ofs << "----------------------------------------\n\n";

    for (const auto& r : results) {
        ofs << "  [" << r.algorithm << "] " << r.operation << "\n";
        ofs << std::fixed << std::setprecision(4);
        ofs << "    Iterations     : " << r.iterations        << "\n";
        ofs << "    Mean           : " << r.mean_us           << " us\n";
        ofs << "    Median         : " << r.median_us         << " us\n";
        ofs << "    Minimum        : " << r.min_us            << " us\n";
        ofs << "    Maximum        : " << r.max_us            << " us\n";
        ofs << "    Std Dev        : " << r.stddev_us         << " us\n";
        ofs << "    95% CI         : ±" << r.ci95_us          << " us\n";
        ofs << std::setprecision(2);
        ofs << "    Ops/sec        : " << r.ops_per_sec       << "\n";
        ofs << std::setprecision(4);
        ofs << "    Rel. Slowdown  : " << r.relative_slowdown << "x\n";
        ofs << "    Overhead       : " << r.pct_overhead      << " %\n\n";
    }

    ofs << "========================================\n";
    ofs << " End of Log\n";
    ofs << "========================================\n";

    ofs.close();
    std::cout << "[OK] Log written: " << filepath << "\n";
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

    std::cout << "Simulation Parameters\n";
    std::cout << "  Kernel image size   : " << KERNEL_SIZE / (1024 * 1024) << " MB\n";
    std::cout << "  Warm-up iterations  : " << WARMUP_ITERATIONS << "\n";
    std::cout << "  Boot verifications  : " << VERIFY_ITERATIONS << "\n";
    std::cout << "\n";

    // ------------------------------------------------------------------
    // Create synthetic kernel binary
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " Creating Synthetic Kernel Image\n";
    print_separator();
    std::cout << "\n";

    std::vector<unsigned char> kernel(KERNEL_SIZE);
    if (RAND_bytes(kernel.data(), static_cast<int>(KERNEL_SIZE)) != 1) {
        std::cerr << "[ERROR] Failed to generate random kernel image\n";
        return 1;
    }
    std::cout << "  Generated " << KERNEL_SIZE / (1024 * 1024)
              << " MB kernel image (random bytes)\n\n";

    // Record start time
    auto suite_start = BenchClock::now();
    long mem_before = get_peak_rss_kb();

    // Storage for verification results
    std::vector<BenchmarkStats> all_results;

    // ------------------------------------------------------------------
    // RSA-2048 Secure Boot
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " RSA-2048 Secure Boot Simulation\n";
    print_separator();
    std::cout << "\n";

    BootBenchResult rsa_boot = bench_rsa_boot(
        kernel.data(), KERNEL_SIZE, WARMUP_ITERATIONS, VERIFY_ITERATIONS);

    auto rsa_verify_stats = compute_stats("RSA-2048", "Boot Verification",
                                          rsa_boot.verify_durations_us,
                                          VERIFY_ITERATIONS);
    std::cout << "\n";
    print_stat_line(rsa_verify_stats);
    all_results.push_back(rsa_verify_stats);

    // ------------------------------------------------------------------
    // ML-DSA-65 Secure Boot
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " ML-DSA-65 Secure Boot Simulation\n";
    print_separator();
    std::cout << "\n";

    BootBenchResult mldsa_boot = bench_mldsa_boot(
        kernel.data(), KERNEL_SIZE, WARMUP_ITERATIONS, VERIFY_ITERATIONS);

    auto mldsa_verify_stats = compute_stats("ML-DSA-65", "Boot Verification",
                                            mldsa_boot.verify_durations_us,
                                            VERIFY_ITERATIONS);
    std::cout << "\n";
    print_stat_line(mldsa_verify_stats);
    all_results.push_back(mldsa_verify_stats);

    // ------------------------------------------------------------------
    // Relative comparisons
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " Comparative Analysis\n";
    print_separator();
    std::cout << "\n";

    compute_relative(all_results[0], all_results[1]);

    std::cout << std::fixed;
    std::cout << "  Signing (Build-Time):\n";
    std::cout << std::setprecision(2);
    std::cout << "    RSA-2048    : " << rsa_boot.sign_time_us   << " us ("
              << rsa_boot.sign_time_us / 1000.0 << " ms)\n";
    std::cout << "    ML-DSA-65   : " << mldsa_boot.sign_time_us << " us ("
              << mldsa_boot.sign_time_us / 1000.0 << " ms)\n\n";

    std::cout << std::setprecision(4);
    std::cout << "  Boot Verification:\n";
    std::cout << "    ML-DSA-65 vs RSA-2048 : "
              << all_results[1].relative_slowdown << "x  ("
              << all_results[1].pct_overhead << "% overhead)\n\n";

    std::cout << std::setprecision(2);
    std::cout << "  Throughput:\n";
    std::cout << "    RSA-2048    : " << all_results[0].ops_per_sec
              << " verifications/sec\n";
    std::cout << "    ML-DSA-65   : " << all_results[1].ops_per_sec
              << " verifications/sec\n\n";

    // Boot time impact (how much verification adds to boot)
    std::cout << "  Boot Time Impact (single verification):\n";
    std::cout << std::setprecision(4);
    std::cout << "    RSA-2048    : " << all_results[0].median_us / 1000.0 << " ms\n";
    std::cout << "    ML-DSA-65   : " << all_results[1].median_us / 1000.0 << " ms\n";
    std::cout << "\n";

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

    std::string results_dir = "results";

    write_csv(results_dir + "/secure_boot_results.csv", all_results, sysinfo);

    write_boot_json(results_dir + "/secure_boot_results.json",
                    all_results, sysinfo, EXPERIMENT_NAME,
                    KERNEL_SIZE,
                    rsa_boot.sign_time_us, mldsa_boot.sign_time_us);

    write_boot_log(results_dir + "/secure_boot_benchmark.log",
                   all_results, sysinfo, EXPERIMENT_NAME,
                   total_elapsed_sec, KERNEL_SIZE,
                   rsa_boot.sign_time_us, mldsa_boot.sign_time_us);

    std::cout << "\n";
    print_separator();
    std::cout << " Experiment 3 Complete\n";
    print_separator();

    return 0;
}
