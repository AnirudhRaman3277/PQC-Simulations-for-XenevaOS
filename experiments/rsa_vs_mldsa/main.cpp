/*
 * main.cpp
 *
 * Experiment 2: RSA-2048 vs ML-DSA-65
 * Secure Boot / Driver Authentication / Kernel Module Signing
 *
 * Driver program that executes all benchmarks for Experiment 2,
 * computes statistics, measures key/signature sizes, and writes
 * results to CSV, JSON, and log files.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 * Scope:   Stage 1 — C++ Benchmark Engine
 */

#include "benchmark.h"

// ============================================================================
// Configuration
// ============================================================================

static constexpr size_t WARMUP_ITERATIONS  = 100;
static constexpr size_t MEASURE_ITERATIONS = 100;

static const char* EXPERIMENT_NAME =
    "Experiment 2: RSA-2048 vs ML-DSA-65 — Digital Signatures";

// ============================================================================
// Extended JSON Output (includes key sizes)
// ============================================================================

static void write_json_with_sizes(const std::string& filepath,
                                  const std::vector<BenchmarkStats>& results,
                                  const SystemInfo& sysinfo,
                                  const std::string& experiment_name,
                                  const KeySizeInfo& rsa_sizes,
                                  const KeySizeInfo& mldsa_sizes) {
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

    // Key sizes
    ofs << "  \"key_sizes\": [\n";

    auto write_size_entry = [&](const KeySizeInfo& ks, bool last) {
        ofs << "    {\n";
        ofs << "      \"algorithm\": \""      << json_escape(ks.algorithm) << "\",\n";
        ofs << "      \"public_key_bytes\": "  << ks.public_key_bytes     << ",\n";
        ofs << "      \"private_key_bytes\": " << ks.private_key_bytes    << ",\n";
        ofs << "      \"signature_bytes\": "   << ks.signature_bytes      << "\n";
        ofs << "    }";
        if (!last) ofs << ",";
        ofs << "\n";
    };

    write_size_entry(rsa_sizes, false);
    write_size_entry(mldsa_sizes, true);
    ofs << "  ],\n";

    // Timing results
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
// Extended Log Output (includes key sizes)
// ============================================================================

static void write_log_with_sizes(const std::string& filepath,
                                 const std::vector<BenchmarkStats>& results,
                                 const SystemInfo& sysinfo,
                                 const std::string& experiment_name,
                                 double total_elapsed_sec,
                                 const KeySizeInfo& rsa_sizes,
                                 const KeySizeInfo& mldsa_sizes) {
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
    ofs << "  Compiler     : " << sysinfo.compiler << " " << sysinfo.compiler_version << "\n";
    ofs << "  Opt. Flags   : " << sysinfo.optimization_flags << "\n";
    ofs << "  OpenSSL      : " << sysinfo.openssl_version  << "\n";
    ofs << "  CPU          : " << sysinfo.cpu_vendor << " " << sysinfo.cpu_model << "\n";
    ofs << "  CPU Arch     : " << sysinfo.cpu_arch << "\n";
    ofs << "  Cores        : " << sysinfo.physical_cores << " Physical / " << sysinfo.logical_cores << " Logical\n";
    ofs << "  OS & Kernel  : " << sysinfo.os_name << " " << sysinfo.kernel_version   << "\n";
    ofs << "  RAM          : " << sysinfo.ram_info         << "\n";
    ofs << "  Time         : " << sysinfo.timestamp        << "\n";
    ofs << "  Duration     : " << std::fixed << std::setprecision(2)
        << total_elapsed_sec << " seconds\n\n";

    // Key sizes section
    ofs << "----------------------------------------\n";
    ofs << " Key & Signature Sizes (DER-encoded)\n";
    ofs << "----------------------------------------\n\n";

    auto log_sizes = [&](const KeySizeInfo& ks) {
        ofs << "  [" << ks.algorithm << "]\n";
        ofs << "    Public Key  : " << ks.public_key_bytes  << " bytes\n";
        ofs << "    Private Key : " << ks.private_key_bytes << " bytes\n";
        ofs << "    Signature   : " << ks.signature_bytes   << " bytes\n\n";
    };

    log_sizes(rsa_sizes);
    log_sizes(mldsa_sizes);

    if (rsa_sizes.public_key_bytes > 0 && mldsa_sizes.public_key_bytes > 0) {
        ofs << "  Size Ratios (ML-DSA-65 / RSA-2048):\n";
        ofs << std::setprecision(2);
        ofs << "    Public Key  : "
            << static_cast<double>(mldsa_sizes.public_key_bytes) /
               static_cast<double>(rsa_sizes.public_key_bytes)
            << "x\n";
        ofs << "    Private Key : "
            << static_cast<double>(mldsa_sizes.private_key_bytes) /
               static_cast<double>(rsa_sizes.private_key_bytes)
            << "x\n";
        ofs << "    Signature   : "
            << static_cast<double>(mldsa_sizes.signature_bytes) /
               static_cast<double>(rsa_sizes.signature_bytes)
            << "x\n\n";
    }

    // Timing results
    ofs << "----------------------------------------\n";
    ofs << " Timing Results\n";
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

static void print_sizes(const KeySizeInfo& ks) {
    std::cout << "  [" << ks.algorithm << "]\n";
    std::cout << "    Public Key  : " << ks.public_key_bytes  << " bytes\n";
    std::cout << "    Private Key : " << ks.private_key_bytes << " bytes\n";
    std::cout << "    Signature   : " << ks.signature_bytes   << " bytes\n";
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
    std::cout << "  Test message size   : 256 bytes\n";
    std::cout << "\n";

    // ------------------------------------------------------------------
    // Key & Signature Sizes
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " Key & Signature Sizes (DER-encoded)\n";
    print_separator();
    std::cout << "\n";

    KeySizeInfo rsa_sizes   = measure_rsa_sizes();
    KeySizeInfo mldsa_sizes = measure_mldsa_sizes();

    print_sizes(rsa_sizes);
    print_sizes(mldsa_sizes);

    if (rsa_sizes.public_key_bytes > 0 && mldsa_sizes.public_key_bytes > 0) {
        std::cout << "  Size Ratios (ML-DSA-65 / RSA-2048):\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "    Public Key  : "
                  << static_cast<double>(mldsa_sizes.public_key_bytes) /
                     static_cast<double>(rsa_sizes.public_key_bytes)
                  << "x\n";
        std::cout << "    Private Key : "
                  << static_cast<double>(mldsa_sizes.private_key_bytes) /
                     static_cast<double>(rsa_sizes.private_key_bytes)
                  << "x\n";
        std::cout << "    Signature   : "
                  << static_cast<double>(mldsa_sizes.signature_bytes) /
                     static_cast<double>(rsa_sizes.signature_bytes)
                  << "x\n";
        std::cout << "\n";
    }

    // Record start time
    auto suite_start = BenchClock::now();
    long mem_before = get_peak_rss_kb();

    // Storage for all results
    std::vector<BenchmarkStats> all_results;

    // ------------------------------------------------------------------
    // RSA-2048
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " RSA-2048 Benchmarks\n";
    print_separator();
    std::cout << "\n";

    std::cout << "[NOTE] RSA-2048 keygen is computationally expensive.\n";
    std::cout << "       This benchmark may take several minutes.\n\n";

    // Keygen
    std::cout << "[RUN] RSA-2048 Key Generation (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto rsa_keygen_times = bench_rsa_keygen(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto rsa_keygen_stats = compute_stats("RSA-2048", "Key Generation",
                                          rsa_keygen_times, MEASURE_ITERATIONS);
    print_stat_line(rsa_keygen_stats);
    all_results.push_back(rsa_keygen_stats);

    // Sign
    std::cout << "[RUN] RSA-2048 Sign (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto rsa_sign_times = bench_rsa_sign(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto rsa_sign_stats = compute_stats("RSA-2048", "Sign",
                                        rsa_sign_times, MEASURE_ITERATIONS);
    print_stat_line(rsa_sign_stats);
    all_results.push_back(rsa_sign_stats);

    // Verify
    std::cout << "[RUN] RSA-2048 Verify (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto rsa_verify_times = bench_rsa_verify(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto rsa_verify_stats = compute_stats("RSA-2048", "Verify",
                                          rsa_verify_times, MEASURE_ITERATIONS);
    print_stat_line(rsa_verify_stats);
    all_results.push_back(rsa_verify_stats);

    // ------------------------------------------------------------------
    // ML-DSA-65
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " ML-DSA-65 Benchmarks\n";
    print_separator();
    std::cout << "\n";

    // Keygen
    std::cout << "[RUN] ML-DSA-65 Key Generation (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto mldsa_keygen_times = bench_mldsa_keygen(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto mldsa_keygen_stats = compute_stats("ML-DSA-65", "Key Generation",
                                            mldsa_keygen_times, MEASURE_ITERATIONS);
    print_stat_line(mldsa_keygen_stats);
    all_results.push_back(mldsa_keygen_stats);

    // Sign
    std::cout << "[RUN] ML-DSA-65 Sign (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto mldsa_sign_times = bench_mldsa_sign(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto mldsa_sign_stats = compute_stats("ML-DSA-65", "Sign",
                                          mldsa_sign_times, MEASURE_ITERATIONS);
    print_stat_line(mldsa_sign_stats);
    all_results.push_back(mldsa_sign_stats);

    // Verify
    std::cout << "[RUN] ML-DSA-65 Verify (" << MEASURE_ITERATIONS << " iterations)...\n";
    auto mldsa_verify_times = bench_mldsa_verify(WARMUP_ITERATIONS, MEASURE_ITERATIONS);
    auto mldsa_verify_stats = compute_stats("ML-DSA-65", "Verify",
                                            mldsa_verify_times, MEASURE_ITERATIONS);
    print_stat_line(mldsa_verify_stats);
    all_results.push_back(mldsa_verify_stats);

    // ------------------------------------------------------------------
    // Relative comparisons
    // ------------------------------------------------------------------
    print_separator();
    std::cout << " Relative Comparisons\n";
    print_separator();
    std::cout << "\n";

    std::cout << std::fixed << std::setprecision(4);

    // Keygen: RSA vs ML-DSA  (index 0 vs 3)
    compute_relative(all_results[0], all_results[3]);
    std::cout << "  Key Generation:\n";
    std::cout << "    ML-DSA-65 vs RSA-2048 : "
              << all_results[3].relative_slowdown << "x  ("
              << all_results[3].pct_overhead << "% overhead)\n\n";

    // Sign: RSA vs ML-DSA  (index 1 vs 4)
    compute_relative(all_results[1], all_results[4]);
    std::cout << "  Signing:\n";
    std::cout << "    ML-DSA-65 vs RSA-2048 : "
              << all_results[4].relative_slowdown << "x  ("
              << all_results[4].pct_overhead << "% overhead)\n\n";

    // Verify: RSA vs ML-DSA  (index 2 vs 5)
    compute_relative(all_results[2], all_results[5]);
    std::cout << "  Verification:\n";
    std::cout << "    ML-DSA-65 vs RSA-2048 : "
              << all_results[5].relative_slowdown << "x  ("
              << all_results[5].pct_overhead << "% overhead)\n\n";

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

    write_csv(results_dir + "/rsa_vs_mldsa_results.csv", all_results, sysinfo);

    write_json_with_sizes(results_dir + "/rsa_vs_mldsa_results.json",
                          all_results, sysinfo, EXPERIMENT_NAME,
                          rsa_sizes, mldsa_sizes);

    write_log_with_sizes(results_dir + "/rsa_vs_mldsa_benchmark.log",
                         all_results, sysinfo, EXPERIMENT_NAME,
                         total_elapsed_sec, rsa_sizes, mldsa_sizes);

    std::cout << "\n";
    print_separator();
    std::cout << " Experiment 2 Complete\n";
    print_separator();

    return 0;
}
