/*
 * benchmark.cpp
 *
 * Experiment 4: Package Verification
 * Package Manager / Software Supply Chain Security
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#include "benchmark.h"
#include <openssl/rsa.h>

using Clock = BenchClock;

// ============================================================================
// Helpers
// ============================================================================

static EVP_PKEY* generate_rsa_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY* generate_mldsa_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr);
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static bool rsa_sign(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                     unsigned char* sig, size_t* sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); return false;
    }
    if (EVP_DigestSign(mdctx, sig, sig_len, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(mdctx); return false;
    }
    EVP_MD_CTX_free(mdctx);
    return true;
}

static bool rsa_verify(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                       const unsigned char* sig, size_t sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;
    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); return false;
    }
    int result = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(mdctx);
    return (result == 1);
}

static bool mldsa_sign(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                       unsigned char* sig, size_t* sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;
    if (EVP_DigestSignInit_ex(mdctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(mdctx); return false;
    }
    if (EVP_DigestSign(mdctx, sig, sig_len, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(mdctx); return false;
    }
    EVP_MD_CTX_free(mdctx);
    return true;
}

static bool mldsa_verify(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                         const unsigned char* sig, size_t sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;
    if (EVP_DigestVerifyInit_ex(mdctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(mdctx); return false;
    }
    int result = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(mdctx);
    return (result == 1);
}

// ============================================================================
// Benchmarks
// ============================================================================

std::vector<double> bench_rsa_package_batch(const unsigned char* pkg, size_t pkg_size,
                                            size_t batch_size,
                                            size_t warmup, size_t iterations) {
    EVP_PKEY* key = generate_rsa_key();
    if (!key) return {};

    unsigned char sig[512];
    size_t sig_len = sizeof(sig);
    if (!rsa_sign(key, pkg, pkg_size, sig, &sig_len)) {
        EVP_PKEY_free(key);
        return {};
    }

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        for (size_t b = 0; b < batch_size; ++b) {
            rsa_verify(key, pkg, pkg_size, sig, sig_len);
        }
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        bool ok = true;
        for (size_t b = 0; b < batch_size; ++b) {
            if (!rsa_verify(key, pkg, pkg_size, sig, sig_len)) {
                ok = false;
                break;
            }
        }
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("RSA package batch verify");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(key);
    return durations;
}

std::vector<double> bench_mldsa_package_batch(const unsigned char* pkg, size_t pkg_size,
                                              size_t batch_size,
                                              size_t warmup, size_t iterations) {
    EVP_PKEY* key = generate_mldsa_key();
    if (!key) return {};

    unsigned char sig[4096];
    size_t sig_len = sizeof(sig);
    if (!mldsa_sign(key, pkg, pkg_size, sig, &sig_len)) {
        EVP_PKEY_free(key);
        return {};
    }

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        for (size_t b = 0; b < batch_size; ++b) {
            mldsa_verify(key, pkg, pkg_size, sig, sig_len);
        }
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        bool ok = true;
        for (size_t b = 0; b < batch_size; ++b) {
            if (!mldsa_verify(key, pkg, pkg_size, sig, sig_len)) {
                ok = false;
                break;
            }
        }
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("ML-DSA package batch verify");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(key);
    return durations;
}
