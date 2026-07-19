/*
 * benchmark.h
 *
 * Experiment 2: RSA-2048 vs ML-DSA-65
 * Secure Boot / Driver Authentication / Kernel Module Signing
 *
 * Evaluates digital signature primitives for XenevaOS secure boot,
 * driver authentication, and kernel module verification.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#ifndef RSA_VS_MLDSA_BENCHMARK_H
#define RSA_VS_MLDSA_BENCHMARK_H

#include "benchmark_common.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/x509.h>

// ============================================================================
// Key / Signature Size Information
// ============================================================================

struct KeySizeInfo {
    std::string algorithm;
    size_t public_key_bytes;
    size_t private_key_bytes;
    size_t signature_bytes;
};

// ============================================================================
// RSA-2048 Benchmark Functions
// ============================================================================

/**
 * Benchmark RSA-2048 key generation.
 * Note: RSA keygen is significantly slower than other operations.
 */
std::vector<double> bench_rsa_keygen(size_t warmup, size_t iterations);

/**
 * Benchmark RSA-2048 signing (SHA-256).
 * Signs a fixed 256-byte test message with a pre-generated key.
 */
std::vector<double> bench_rsa_sign(size_t warmup, size_t iterations);

/**
 * Benchmark RSA-2048 verification (SHA-256).
 * Verifies a pre-generated signature against a fixed test message.
 */
std::vector<double> bench_rsa_verify(size_t warmup, size_t iterations);

// ============================================================================
// ML-DSA-65 Benchmark Functions
// ============================================================================

/**
 * Benchmark ML-DSA-65 key generation.
 */
std::vector<double> bench_mldsa_keygen(size_t warmup, size_t iterations);

/**
 * Benchmark ML-DSA-65 signing.
 * Signs a fixed 256-byte test message with a pre-generated key.
 */
std::vector<double> bench_mldsa_sign(size_t warmup, size_t iterations);

/**
 * Benchmark ML-DSA-65 verification.
 * Verifies a pre-generated signature against a fixed test message.
 */
std::vector<double> bench_mldsa_verify(size_t warmup, size_t iterations);

// ============================================================================
// Key Size Measurement
// ============================================================================

/**
 * Measure RSA-2048 key and signature sizes (DER-encoded).
 */
KeySizeInfo measure_rsa_sizes();

/**
 * Measure ML-DSA-65 key and signature sizes (DER-encoded).
 */
KeySizeInfo measure_mldsa_sizes();

#endif // RSA_VS_MLDSA_BENCHMARK_H
