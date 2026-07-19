/*
 * benchmark.cpp
 *
 * Experiment 2: RSA-2048 vs ML-DSA-65
 * Secure Boot / Driver Authentication / Kernel Module Signing
 *
 * Implementation of benchmark routines using OpenSSL 3.x EVP APIs.
 * RSA-2048 uses SHA-256 for signing/verification.
 * ML-DSA-65 uses the FIPS 204 standardized algorithm available
 * natively in OpenSSL 3.5.x.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#include "benchmark.h"

using Clock = BenchClock;

// ============================================================================
// Shared test message (256 bytes, simulates a kernel module hash / payload)
// ============================================================================

static constexpr size_t TEST_MSG_LEN = 256;
static unsigned char g_test_msg[TEST_MSG_LEN];
static bool g_test_msg_initialized = false;

static void ensure_test_message() {
    if (!g_test_msg_initialized) {
        RAND_bytes(g_test_msg, TEST_MSG_LEN);
        g_test_msg_initialized = true;
    }
}

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
// RSA-2048 Benchmarks
// ============================================================================

std::vector<double> bench_rsa_keygen(size_t warmup, size_t iterations) {
    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        EVP_PKEY* k = generate_rsa_key();
        EVP_PKEY_free(k);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        EVP_PKEY* k = generate_rsa_key();
        auto t1 = Clock::now();

        if (!k) {
            openssl_print_errors("RSA keygen");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
        EVP_PKEY_free(k);
    }

    return durations;
}

std::vector<double> bench_rsa_sign(size_t warmup, size_t iterations) {
    ensure_test_message();

    EVP_PKEY* key = generate_rsa_key();
    if (!key) {
        std::cerr << "[ERROR] Failed to generate RSA key for sign bench\n";
        return {};
    }

    unsigned char sig[512];
    size_t sig_len;

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        sig_len = sizeof(sig);
        rsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        sig_len = sizeof(sig);

        auto t0 = Clock::now();
        bool ok = rsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("RSA sign");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(key);
    return durations;
}

std::vector<double> bench_rsa_verify(size_t warmup, size_t iterations) {
    ensure_test_message();

    // Pre-generate key and signature
    EVP_PKEY* key = generate_rsa_key();
    if (!key) {
        std::cerr << "[ERROR] Failed to generate RSA key for verify bench\n";
        return {};
    }

    unsigned char sig[512];
    size_t sig_len = sizeof(sig);
    if (!rsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len)) {
        std::cerr << "[ERROR] Failed to sign for RSA verify bench setup\n";
        EVP_PKEY_free(key);
        return {};
    }

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        rsa_verify(key, g_test_msg, TEST_MSG_LEN, sig, sig_len);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        bool ok = rsa_verify(key, g_test_msg, TEST_MSG_LEN, sig, sig_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("RSA verify");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(key);
    return durations;
}

// ============================================================================
// ML-DSA-65 Benchmarks
// ============================================================================

std::vector<double> bench_mldsa_keygen(size_t warmup, size_t iterations) {
    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        EVP_PKEY* k = generate_mldsa_key();
        EVP_PKEY_free(k);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        EVP_PKEY* k = generate_mldsa_key();
        auto t1 = Clock::now();

        if (!k) {
            openssl_print_errors("ML-DSA keygen");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
        EVP_PKEY_free(k);
    }

    return durations;
}

std::vector<double> bench_mldsa_sign(size_t warmup, size_t iterations) {
    ensure_test_message();

    EVP_PKEY* key = generate_mldsa_key();
    if (!key) {
        std::cerr << "[ERROR] Failed to generate ML-DSA key for sign bench\n";
        return {};
    }

    unsigned char sig[4096];
    size_t sig_len;

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        sig_len = sizeof(sig);
        mldsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        sig_len = sizeof(sig);

        auto t0 = Clock::now();
        bool ok = mldsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("ML-DSA sign");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(key);
    return durations;
}

std::vector<double> bench_mldsa_verify(size_t warmup, size_t iterations) {
    ensure_test_message();

    // Pre-generate key and signature
    EVP_PKEY* key = generate_mldsa_key();
    if (!key) {
        std::cerr << "[ERROR] Failed to generate ML-DSA key for verify bench\n";
        return {};
    }

    unsigned char sig[4096];
    size_t sig_len = sizeof(sig);
    if (!mldsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len)) {
        std::cerr << "[ERROR] Failed to sign for ML-DSA verify bench setup\n";
        EVP_PKEY_free(key);
        return {};
    }

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        mldsa_verify(key, g_test_msg, TEST_MSG_LEN, sig, sig_len);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        bool ok = mldsa_verify(key, g_test_msg, TEST_MSG_LEN, sig, sig_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("ML-DSA verify");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(key);
    return durations;
}

// ============================================================================
// Key Size Measurement
// ============================================================================

KeySizeInfo measure_rsa_sizes() {
    KeySizeInfo info;
    info.algorithm = "RSA-2048";
    info.public_key_bytes  = 0;
    info.private_key_bytes = 0;
    info.signature_bytes   = 0;

    EVP_PKEY* key = generate_rsa_key();
    if (!key) {
        std::cerr << "[ERROR] Cannot measure RSA key sizes\n";
        return info;
    }

    // Public key size (DER-encoded SubjectPublicKeyInfo)
    int pub_len = i2d_PUBKEY(key, nullptr);
    if (pub_len > 0) info.public_key_bytes = static_cast<size_t>(pub_len);

    // Private key size (DER-encoded PrivateKeyInfo)
    int priv_len = i2d_PrivateKey(key, nullptr);
    if (priv_len > 0) info.private_key_bytes = static_cast<size_t>(priv_len);

    // Actual signature size
    ensure_test_message();
    unsigned char sig[512];
    size_t sig_len = sizeof(sig);
    if (rsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len)) {
        info.signature_bytes = sig_len;
    }

    EVP_PKEY_free(key);
    return info;
}

KeySizeInfo measure_mldsa_sizes() {
    KeySizeInfo info;
    info.algorithm = "ML-DSA-65";
    info.public_key_bytes  = 0;
    info.private_key_bytes = 0;
    info.signature_bytes   = 0;

    EVP_PKEY* key = generate_mldsa_key();
    if (!key) {
        std::cerr << "[ERROR] Cannot measure ML-DSA key sizes\n";
        return info;
    }

    // Public key size (DER-encoded SubjectPublicKeyInfo)
    int pub_len = i2d_PUBKEY(key, nullptr);
    if (pub_len > 0) info.public_key_bytes = static_cast<size_t>(pub_len);

    // Private key size (DER-encoded PrivateKeyInfo)
    int priv_len = i2d_PrivateKey(key, nullptr);
    if (priv_len > 0) info.private_key_bytes = static_cast<size_t>(priv_len);

    // Actual signature size
    ensure_test_message();
    unsigned char sig[4096];
    size_t sig_len = sizeof(sig);
    if (mldsa_sign(key, g_test_msg, TEST_MSG_LEN, sig, &sig_len)) {
        info.signature_bytes = sig_len;
    }

    EVP_PKEY_free(key);
    return info;
}
