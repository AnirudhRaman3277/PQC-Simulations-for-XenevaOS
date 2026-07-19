/*
 * benchmark.h
 *
 * Experiment 3: Secure Boot Simulation
 * Trusted Boot / Kernel Integrity
 *
 * Simulates the secure boot verification pipeline:
 *   1. Create a synthetic kernel binary (4 MB)
 *   2. Sign with RSA-2048 (SHA-256) or ML-DSA-65
 *   3. Verify the signature 1000 times (simulating repeated boots)
 *
 * Measures verification latency and throughput — the critical
 * metrics for boot-time performance.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#ifndef SECURE_BOOT_BENCHMARK_H
#define SECURE_BOOT_BENCHMARK_H

#include "benchmark_common.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

// ============================================================================
// Secure Boot Simulation Result
// ============================================================================

struct BootBenchResult {
    double sign_time_us;                     // Time to sign the kernel image
    std::vector<double> verify_durations_us; // Per-verification timings
};

// ============================================================================
// Benchmark Functions
// ============================================================================

/**
 * Simulate RSA-2048 secure boot.
 * Generates an RSA-2048 key, signs the kernel binary once (timed),
 * then verifies the signature `iterations` times.
 * Uses SHA-256 for the digest.
 */
BootBenchResult bench_rsa_boot(const unsigned char* kernel, size_t kernel_size,
                               size_t warmup, size_t iterations);

/**
 * Simulate ML-DSA-65 secure boot.
 * Generates an ML-DSA-65 key, signs the kernel binary once (timed),
 * then verifies the signature `iterations` times.
 */
BootBenchResult bench_mldsa_boot(const unsigned char* kernel, size_t kernel_size,
                                 size_t warmup, size_t iterations);

#endif // SECURE_BOOT_BENCHMARK_H
