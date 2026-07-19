/*
 * benchmark.h
 *
 * Experiment 1: ECDH P-256 vs ML-KEM-768
 * Kernel Crypto Framework / Secure Session Establishment
 *
 * Evaluates key exchange primitives for XenevaOS kernel-level
 * session establishment and XR runtime secure channels.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#ifndef ECDH_VS_MLKEM_BENCHMARK_H
#define ECDH_VS_MLKEM_BENCHMARK_H

#include "benchmark_common.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

// ============================================================================
// ECDH P-256 Benchmark Functions
// ============================================================================

/**
 * Benchmark ECDH P-256 key generation.
 * Measures the time to generate an EC key pair on the prime256v1 curve.
 */
std::vector<double> bench_ecdh_keygen(size_t warmup, size_t iterations);

/**
 * Benchmark ECDH P-256 shared secret derivation.
 * Measures the full key exchange: two key pairs generated, then
 * shared secret derived via ECDH.
 */
std::vector<double> bench_ecdh_shared_secret(size_t warmup, size_t iterations);

/**
 * Benchmark ECDH P-256 full key exchange latency.
 * Measures end-to-end: keygen for both parties + derivation.
 */
std::vector<double> bench_ecdh_key_exchange(size_t warmup, size_t iterations);

// ============================================================================
// ML-KEM-768 Benchmark Functions
// ============================================================================

/**
 * Benchmark ML-KEM-768 key generation.
 * Measures the time to generate an ML-KEM-768 key pair via EVP_PKEY_keygen.
 */
std::vector<double> bench_mlkem_keygen(size_t warmup, size_t iterations);

/**
 * Benchmark ML-KEM-768 encapsulation.
 * Measures the time to encapsulate (generate ciphertext + shared secret).
 */
std::vector<double> bench_mlkem_encaps(size_t warmup, size_t iterations);

/**
 * Benchmark ML-KEM-768 decapsulation.
 * Measures the time to decapsulate (recover shared secret from ciphertext).
 */
std::vector<double> bench_mlkem_decaps(size_t warmup, size_t iterations);

/**
 * Benchmark ML-KEM-768 full key exchange latency.
 * Measures end-to-end: keygen + encaps + decaps.
 */
std::vector<double> bench_mlkem_key_exchange(size_t warmup, size_t iterations);

#endif // ECDH_VS_MLKEM_BENCHMARK_H
