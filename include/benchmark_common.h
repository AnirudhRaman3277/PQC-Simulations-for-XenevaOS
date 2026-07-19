/*
 * benchmark_common.h
 * Common benchmark infrastructure for the PQC Benchmark Suite.
 */
#ifndef BENCHMARK_COMMON_H
#define BENCHMARK_COMMON_H

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

// High-resolution monotonic timer suitable for benchmarking
using BenchClock = std::chrono::steady_clock;

// ============================================================================
// Statistics
// ============================================================================

struct BenchmarkStats {
    std::string algorithm;
    std::string operation;
    double mean_us;
    double median_us;
    double min_us;
    double max_us;
    double variance_us;
    double stddev_us;
    double ci95_us;
    double ops_per_sec;
    double relative_slowdown;
    double pct_overhead;
    size_t iterations;
};

inline BenchmarkStats compute_stats(const std::string& algorithm,
                                     const std::string& operation,
                                     std::vector<double>& durations_us,
                                     size_t iterations) {
    BenchmarkStats s;
    s.algorithm  = algorithm;
    s.operation  = operation;
    s.iterations = iterations;

    std::sort(durations_us.begin(), durations_us.end());
    size_t n = durations_us.size();

    double sum = std::accumulate(durations_us.begin(), durations_us.end(), 0.0);
    s.mean_us = sum / static_cast<double>(n);

    if (n % 2 == 0) {
        s.median_us = (durations_us[n / 2 - 1] + durations_us[n / 2]) / 2.0;
    } else {
        s.median_us = durations_us[n / 2];
    }

    s.min_us = durations_us.front();
    s.max_us = durations_us.back();

    double sq_sum = 0.0;
    for (double v : durations_us) {
        double diff = v - s.mean_us;
        sq_sum += diff * diff;
    }
    s.variance_us = sq_sum / static_cast<double>(n - 1);
    s.stddev_us   = std::sqrt(s.variance_us);

    s.ci95_us = 1.96 * s.stddev_us / std::sqrt(static_cast<double>(n));
    s.ops_per_sec = (s.mean_us > 0.0) ? 1'000'000.0 / s.mean_us : 0.0;

    s.relative_slowdown = 1.0;
    s.pct_overhead      = 0.0;

    return s;
}

inline void compute_relative(BenchmarkStats& classical, BenchmarkStats& pq) {
    if (classical.mean_us > 0.0) {
        pq.relative_slowdown = pq.mean_us / classical.mean_us;
        pq.pct_overhead      = (pq.mean_us - classical.mean_us) / classical.mean_us * 100.0;
    }
    classical.relative_slowdown = 1.0;
    classical.pct_overhead      = 0.0;
}

// ============================================================================
// System Information
// ============================================================================

struct SystemInfo {
    std::string compiler;
    std::string compiler_version;
    std::string optimization_flags;
    std::string openssl_version;
    std::string cpu_vendor;
    std::string cpu_model;
    std::string cpu_arch;
    std::string logical_cores;
    std::string physical_cores;
    std::string os_name;
    std::string kernel_version;
    std::string ram_info;
    std::string timestamp;
};

inline std::string exec_command(const char* cmd) {
    char buffer[256];
    std::string result;
    FILE* pipe = popen(cmd, "r");
    if (pipe) {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);
    }
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

inline void check_cpu_frequency_scaling() {
    std::string governor = exec_command("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null");
    std::string turbo = exec_command("cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null");
    std::string boost = exec_command("cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null");

    bool has_warning = false;
    std::string warning = "\n[WARNING] CPU Frequency Scaling Detected:\n";

    if (!governor.empty() && governor != "performance") {
        warning += "  - CPU governor is set to '" + governor + "' (should be 'performance').\n";
        has_warning = true;
    }
    if (turbo == "0" || boost == "1") {
        warning += "  - Turbo/Precision Boost is ENABLED. This may affect benchmark reproducibility.\n";
        has_warning = true;
    }

    if (has_warning) {
        std::cerr << warning << "\n";
    }
}

#ifndef OPT_FLAGS
#define OPT_FLAGS "Unknown"
#endif

#ifndef COMPILER_ID
#define COMPILER_ID "Unknown"
#endif

inline SystemInfo collect_system_info() {
    SystemInfo info;

    info.compiler = COMPILER_ID;
    info.compiler_version = exec_command("g++ --version | head -1");
    info.optimization_flags = OPT_FLAGS;
    
    info.openssl_version = OpenSSL_version(OPENSSL_VERSION);
    
    info.cpu_vendor = exec_command("lscpu | grep 'Vendor ID' | awk -F ':' '{print $2}' | xargs");
    info.cpu_model = exec_command("lscpu | grep 'Model name' | sed 's/Model name:[[:space:]]*//'");
    info.cpu_arch = exec_command("uname -m");
    info.logical_cores = exec_command("nproc");
    info.physical_cores = exec_command("lscpu | awk '/^Core\\(s\\) per socket:/ {cores=$4} /^Socket\\(s\\):/ {sockets=$2} END {print cores*sockets}'");

    struct utsname uts;
    if (uname(&uts) == 0) {
        info.os_name = uts.sysname;
        info.kernel_version = uts.release;
    }

    info.ram_info = exec_command("free -h | grep Mem | awk '{print $2}'");

    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    char tbuf[64];
    std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S %Z", std::localtime(&t));
    info.timestamp = tbuf;

    check_cpu_frequency_scaling();

    return info;
}

// ============================================================================
// Output Functions
// ============================================================================

inline void write_csv(const std::string& filepath,
                      const std::vector<BenchmarkStats>& results,
                      const SystemInfo& sysinfo) {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Cannot open CSV file: " << filepath << "\n";
        return;
    }

    ofs << "Algorithm,Compiler,CompilerVersion,OptimizationFlags,CPUModel,OS,Timestamp,"
        << "Operation,Iterations,Average(us),Median(us),Minimum(us),Maximum(us),"
        << "StdDev(us),CI95(us),OpsPerSecond,RelativeSlowdown,OverheadPct\n";

    ofs << std::fixed << std::setprecision(4);
    for (const auto& r : results) {
        ofs << r.algorithm << ","
            << sysinfo.compiler << ","
            << "\"" << sysinfo.compiler_version << "\","
            << "\"" << sysinfo.optimization_flags << "\","
            << "\"" << sysinfo.cpu_model << "\","
            << sysinfo.os_name << ","
            << sysinfo.timestamp << ","
            << r.operation << ","
            << r.iterations << ","
            << r.mean_us << ","
            << r.median_us << ","
            << r.min_us << ","
            << r.max_us << ","
            << r.stddev_us << ","
            << r.ci95_us << ","
            << std::setprecision(2)
            << r.ops_per_sec << ","
            << std::setprecision(4)
            << r.relative_slowdown << ","
            << r.pct_overhead << "\n";
    }
    ofs.close();
    std::cout << "[OK] CSV written: " << filepath << "\n";
}

inline std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

inline void write_json(const std::string& filepath,
                       const std::vector<BenchmarkStats>& results,
                       const SystemInfo& sysinfo,
                       const std::string& experiment_name) {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Cannot open JSON file: " << filepath << "\n";
        return;
    }

    ofs << std::fixed;
    ofs << "{\n";
    ofs << "  \"experiment\": \"" << json_escape(experiment_name) << "\",\n";
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
// Benchmark Log
// ============================================================================

inline void write_log(const std::string& filepath,
                      const std::vector<BenchmarkStats>& results,
                      const SystemInfo& sysinfo,
                      const std::string& experiment_name,
                      double total_elapsed_sec) {
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
    ofs << "  Duration     : " << std::fixed << std::setprecision(2) << total_elapsed_sec << " seconds\n\n";

    ofs << "----------------------------------------\n";
    ofs << " Results\n";
    ofs << "----------------------------------------\n\n";

    for (const auto& r : results) {
        ofs << "  [" << r.algorithm << "] " << r.operation << "\n";
        ofs << std::fixed << std::setprecision(4);
        ofs << "    Iterations     : " << r.iterations        << "\n";
        ofs << "    Average        : " << r.mean_us           << " us\n";
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
// OpenSSL Error Handling
// ============================================================================

inline void openssl_print_errors(const std::string& context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "[OpenSSL Error] " << context << ": " << buf << "\n";
    }
}

// ============================================================================
// Memory Usage (Linux /proc/self/status)
// ============================================================================

inline long get_peak_rss_kb() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss; // in KB on Linux
    }
    return -1;
}

#endif // BENCHMARK_COMMON_H
