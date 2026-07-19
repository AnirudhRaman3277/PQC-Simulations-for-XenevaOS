/*
 * benchmark.cpp
 *
 * Experiment 3: Secure Boot Simulation
 * Trusted Boot / Kernel Integrity
 *
 * Implements the secure boot simulation using OpenSSL 3.x EVP APIs.
 * Signs a synthetic kernel image once, then benchmarks repeated
 * verification — the hot path in every boot cycle.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#include "benchmark.h"

#include <openssl/rsa.h>

using Clock = BenchClock;

// ============================================================================
// Helper: Generate an RSA-2048 key
// ============================================================================

static EVP_PKEY* generate_rsa_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// ============================================================================
// Helper: Generate an ML-DSA-65 key
// ============================================================================

static EVP_PKEY* generate_mldsa_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// ============================================================================
// Helper: RSA-2048 sign (SHA-256)
// ============================================================================

static bool rsa_sign(EVP_PKEY* pkey,
                     const unsigned char* msg, size_t msg_len,
                     unsigned char* sig, size_t* sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (EVP_DigestSign(mdctx, sig, sig_len, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);
    return true;
}

// ============================================================================
// Helper: RSA-2048 verify (SHA-256)
// ============================================================================

static bool rsa_verify(EVP_PKEY* pkey,
                       const unsigned char* msg, size_t msg_len,
                       const unsigned char* sig, size_t sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    int result = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(mdctx);
    return (result == 1);
}

// ============================================================================
// Helper: ML-DSA-65 sign
// ============================================================================

static bool mldsa_sign(EVP_PKEY* pkey,
                       const unsigned char* msg, size_t msg_len,
                       unsigned char* sig, size_t* sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    // ML-DSA does not use a separate digest algorithm
    if (EVP_DigestSignInit_ex(mdctx, nullptr, nullptr, nullptr,
                              nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (EVP_DigestSign(mdctx, sig, sig_len, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);
    return true;
}

// ============================================================================
// Helper: ML-DSA-65 verify
// ============================================================================

static bool mldsa_verify(EVP_PKEY* pkey,
                         const unsigned char* msg, size_t msg_len,
                         const unsigned char* sig, size_t sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    if (EVP_DigestVerifyInit_ex(mdctx, nullptr, nullptr, nullptr,
                                nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    int result = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(mdctx);
    return (result == 1);
}

// ============================================================================
// RSA-2048 Secure Boot Simulation
// ============================================================================

BootBenchResult bench_rsa_boot(const unsigned char* kernel, size_t kernel_size,
                               size_t warmup, size_t iterations) {
    BootBenchResult result;
    result.sign_time_us = 0.0;

    // Generate signing key
    std::cout << "  Generating RSA-2048 signing key...\n";
    EVP_PKEY* key = generate_rsa_key();
    if (!key) {
        std::cerr << "[ERROR] Failed to generate RSA key for boot simulation\n";
        openssl_print_errors("RSA keygen");
        return result;
    }

    // Sign the kernel image (timed — represents build-time cost)
    unsigned char sig[512];
    size_t sig_len = sizeof(sig);

    std::cout << "  Signing kernel image (" << kernel_size / (1024 * 1024) << " MB)...\n";
    auto sign_t0 = Clock::now();
    bool sign_ok = rsa_sign(key, kernel, kernel_size, sig, &sig_len);
    auto sign_t1 = Clock::now();

    if (!sign_ok) {
        std::cerr << "[ERROR] RSA kernel signing failed\n";
        openssl_print_errors("RSA boot sign");
        EVP_PKEY_free(key);
        return result;
    }

    result.sign_time_us =
        std::chrono::duration<double, std::micro>(sign_t1 - sign_t0).count();
    std::cout << "  Kernel signed (signature: " << sig_len << " bytes, "
              << std::fixed << std::setprecision(2)
              << result.sign_time_us << " us)\n";

    // Warm-up verification
    std::cout << "  Warming up (" << warmup << " verifications)...\n";
    for (size_t i = 0; i < warmup; ++i) {
        rsa_verify(key, kernel, kernel_size, sig, sig_len);
    }

    // Measured verification (simulates repeated boot cycles)
    std::cout << "  Benchmarking (" << iterations << " boot verifications)...\n";
    result.verify_durations_us.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        bool ok = rsa_verify(key, kernel, kernel_size, sig, sig_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("RSA boot verify");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        result.verify_durations_us.push_back(us);
    }

    EVP_PKEY_free(key);
    return result;
}

// ============================================================================
// ML-DSA-65 Secure Boot Simulation
// ============================================================================

BootBenchResult bench_mldsa_boot(const unsigned char* kernel, size_t kernel_size,
                                 size_t warmup, size_t iterations) {
    BootBenchResult result;
    result.sign_time_us = 0.0;

    // Generate signing key
    std::cout << "  Generating ML-DSA-65 signing key...\n";
    EVP_PKEY* key = generate_mldsa_key();
    if (!key) {
        std::cerr << "[ERROR] Failed to generate ML-DSA key for boot simulation\n";
        openssl_print_errors("ML-DSA keygen");
        return result;
    }

    // Sign the kernel image (timed)
    unsigned char sig[4096];
    size_t sig_len = sizeof(sig);

    std::cout << "  Signing kernel image (" << kernel_size / (1024 * 1024) << " MB)...\n";
    auto sign_t0 = Clock::now();
    bool sign_ok = mldsa_sign(key, kernel, kernel_size, sig, &sig_len);
    auto sign_t1 = Clock::now();

    if (!sign_ok) {
        std::cerr << "[ERROR] ML-DSA kernel signing failed\n";
        openssl_print_errors("ML-DSA boot sign");
        EVP_PKEY_free(key);
        return result;
    }

    result.sign_time_us =
        std::chrono::duration<double, std::micro>(sign_t1 - sign_t0).count();
    std::cout << "  Kernel signed (signature: " << sig_len << " bytes, "
              << std::fixed << std::setprecision(2)
              << result.sign_time_us << " us)\n";

    // Warm-up verification
    std::cout << "  Warming up (" << warmup << " verifications)...\n";
    for (size_t i = 0; i < warmup; ++i) {
        mldsa_verify(key, kernel, kernel_size, sig, sig_len);
    }

    // Measured verification
    std::cout << "  Benchmarking (" << iterations << " boot verifications)...\n";
    result.verify_durations_us.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        bool ok = mldsa_verify(key, kernel, kernel_size, sig, sig_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("ML-DSA boot verify");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        result.verify_durations_us.push_back(us);
    }

    EVP_PKEY_free(key);
    return result;
}
