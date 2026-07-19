/*
 * benchmark.h
 *
 * Experiment 4: Package Verification
 * Package Manager / Software Supply Chain Security
 *
 * Simulates verifying signatures on batches of packages (100, 500, 1000)
 * to measure throughput and latency during large system updates.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#ifndef PACKAGE_VERIFY_BENCHMARK_H
#define PACKAGE_VERIFY_BENCHMARK_H

#include "benchmark_common.h"
#include <openssl/evp.h>

// ============================================================================
// Benchmark Functions
// ============================================================================

/**
 * Benchmark RSA-2048 batch package verification.
 * Signs a 1MB synthetic package, then measures the time to verify it
 * `batch_size` times in a row, repeated for `iterations` to gather stats.
 */
std::vector<double> bench_rsa_package_batch(const unsigned char* pkg, size_t pkg_size,
                                            size_t batch_size,
                                            size_t warmup, size_t iterations);

/**
 * Benchmark ML-DSA-65 batch package verification.
 * Signs a 1MB synthetic package, then measures the time to verify it
 * `batch_size` times in a row, repeated for `iterations` to gather stats.
 */
std::vector<double> bench_mldsa_package_batch(const unsigned char* pkg, size_t pkg_size,
                                              size_t batch_size,
                                              size_t warmup, size_t iterations);

#endif // PACKAGE_VERIFY_BENCHMARK_H
