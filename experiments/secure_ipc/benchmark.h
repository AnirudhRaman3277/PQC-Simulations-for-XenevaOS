/*
 * benchmark.h
 *
 * Experiment 5: Secure IPC Simulation
 * Process Isolation / Secure Messaging
 *
 * Simulates a full secure Inter-Process Communication (IPC) handshake and
 * message exchange:
 *   1. Key Exchange (ECDH P-256 vs ML-KEM-768)
 *   2. Key Derivation (SHA-256)
 *   3. Authenticated Encryption (AES-256-GCM) on a 4KB IPC payload.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#ifndef SECURE_IPC_BENCHMARK_H
#define SECURE_IPC_BENCHMARK_H

#include "benchmark_common.h"
#include <openssl/evp.h>

// ============================================================================
// Benchmark Functions
// ============================================================================

/**
 * Benchmark classical Secure IPC.
 * Uses ECDH (prime256v1) for key exchange, SHA-256 for KDF, and AES-256-GCM
 * to encrypt/decrypt a payload.
 */
std::vector<double> bench_classical_ipc(size_t payload_size, size_t warmup, size_t iterations);

/**
 * Benchmark post-quantum Secure IPC.
 * Uses ML-KEM-768 for key encapsulation, SHA-256 for KDF, and AES-256-GCM
 * to encrypt/decrypt a payload.
 */
std::vector<double> bench_pq_ipc(size_t payload_size, size_t warmup, size_t iterations);

#endif // SECURE_IPC_BENCHMARK_H
