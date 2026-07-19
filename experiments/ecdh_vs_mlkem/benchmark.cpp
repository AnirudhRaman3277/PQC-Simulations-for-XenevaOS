/*
 * benchmark.cpp
 *
 * Experiment 1: ECDH P-256 vs ML-KEM-768
 * Kernel Crypto Framework / Secure Session Establishment
 *
 * Implementation of benchmark routines using OpenSSL 3.x EVP APIs.
 * All PQC operations use the standardized ML-KEM-768 algorithm
 * available natively in OpenSSL 3.5.5.
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#include "benchmark.h"

using Clock = BenchClock;

// ============================================================================
// Helper: Generate an EC key on prime256v1
// ============================================================================

static EVP_PKEY* generate_ec_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>("prime256v1"), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
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
// Helper: ECDH derive shared secret
// ============================================================================

static bool ecdh_derive(EVP_PKEY* our_key, EVP_PKEY* peer_key,
                        unsigned char* secret, size_t* secret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(our_key, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Get required buffer size
    if (EVP_PKEY_derive(ctx, nullptr, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

// ============================================================================
// Helper: Generate an ML-KEM-768 key
// ============================================================================

static EVP_PKEY* generate_mlkem_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr);
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
// Helper: ML-KEM encapsulate
// ============================================================================

static bool mlkem_encapsulate(EVP_PKEY* recipient_pubkey,
                              unsigned char* ciphertext, size_t* ct_len,
                              unsigned char* shared_secret, size_t* ss_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, recipient_pubkey, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Get sizes
    if (EVP_PKEY_encapsulate(ctx, nullptr, ct_len, nullptr, ss_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_encapsulate(ctx, ciphertext, ct_len, shared_secret, ss_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

// ============================================================================
// Helper: ML-KEM decapsulate
// ============================================================================

static bool mlkem_decapsulate(EVP_PKEY* recipient_key,
                              const unsigned char* ciphertext, size_t ct_len,
                              unsigned char* shared_secret, size_t* ss_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, recipient_key, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Get expected shared secret size
    if (EVP_PKEY_decapsulate(ctx, nullptr, ss_len, ciphertext, ct_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_decapsulate(ctx, shared_secret, ss_len, ciphertext, ct_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

// ============================================================================
// ECDH P-256 Benchmarks
// ============================================================================

std::vector<double> bench_ecdh_keygen(size_t warmup, size_t iterations) {
    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        EVP_PKEY* k = generate_ec_key();
        EVP_PKEY_free(k);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        EVP_PKEY* k = generate_ec_key();
        auto t1 = Clock::now();

        if (!k) {
            openssl_print_errors("ECDH keygen");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
        EVP_PKEY_free(k);
    }

    return durations;
}

std::vector<double> bench_ecdh_shared_secret(size_t warmup, size_t iterations) {
    // Pre-generate key pairs for shared secret derivation
    EVP_PKEY* alice = generate_ec_key();
    EVP_PKEY* bob   = generate_ec_key();
    if (!alice || !bob) {
        std::cerr << "[ERROR] Failed to generate ECDH keys for shared secret bench\n";
        EVP_PKEY_free(alice);
        EVP_PKEY_free(bob);
        return {};
    }

    unsigned char secret[64];
    size_t secret_len;

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        secret_len = sizeof(secret);
        ecdh_derive(alice, bob, secret, &secret_len);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        secret_len = sizeof(secret);

        auto t0 = Clock::now();
        bool ok = ecdh_derive(alice, bob, secret, &secret_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("ECDH derive");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
    return durations;
}

std::vector<double> bench_ecdh_key_exchange(size_t warmup, size_t iterations) {
    unsigned char secret[64];
    size_t secret_len;

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        EVP_PKEY* a = generate_ec_key();
        EVP_PKEY* b = generate_ec_key();
        secret_len = sizeof(secret);
        ecdh_derive(a, b, secret, &secret_len);
        EVP_PKEY_free(a);
        EVP_PKEY_free(b);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();

        EVP_PKEY* a = generate_ec_key();
        EVP_PKEY* b = generate_ec_key();
        secret_len = sizeof(secret);
        bool ok = ecdh_derive(a, b, secret, &secret_len);

        auto t1 = Clock::now();

        EVP_PKEY_free(a);
        EVP_PKEY_free(b);

        if (!ok) {
            openssl_print_errors("ECDH key exchange");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    return durations;
}

// ============================================================================
// ML-KEM-768 Benchmarks
// ============================================================================

std::vector<double> bench_mlkem_keygen(size_t warmup, size_t iterations) {
    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        EVP_PKEY* k = generate_mlkem_key();
        EVP_PKEY_free(k);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();
        EVP_PKEY* k = generate_mlkem_key();
        auto t1 = Clock::now();

        if (!k) {
            openssl_print_errors("ML-KEM keygen");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
        EVP_PKEY_free(k);
    }

    return durations;
}

std::vector<double> bench_mlkem_encaps(size_t warmup, size_t iterations) {
    // Pre-generate a recipient key pair
    EVP_PKEY* recipient = generate_mlkem_key();
    if (!recipient) {
        std::cerr << "[ERROR] Failed to generate ML-KEM key for encaps bench\n";
        return {};
    }

    unsigned char ciphertext[2048];
    unsigned char shared_secret[64];
    size_t ct_len, ss_len;

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        ct_len = sizeof(ciphertext);
        ss_len = sizeof(shared_secret);
        mlkem_encapsulate(recipient, ciphertext, &ct_len,
                          shared_secret, &ss_len);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        ct_len = sizeof(ciphertext);
        ss_len = sizeof(shared_secret);

        auto t0 = Clock::now();
        bool ok = mlkem_encapsulate(recipient, ciphertext, &ct_len,
                                    shared_secret, &ss_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("ML-KEM encaps");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(recipient);
    return durations;
}

std::vector<double> bench_mlkem_decaps(size_t warmup, size_t iterations) {
    // Pre-generate a recipient key pair and an encapsulated ciphertext
    EVP_PKEY* recipient = generate_mlkem_key();
    if (!recipient) {
        std::cerr << "[ERROR] Failed to generate ML-KEM key for decaps bench\n";
        return {};
    }

    unsigned char ciphertext[2048];
    unsigned char encaps_secret[64];
    size_t ct_len = sizeof(ciphertext);
    size_t ss_len = sizeof(encaps_secret);

    if (!mlkem_encapsulate(recipient, ciphertext, &ct_len,
                           encaps_secret, &ss_len)) {
        std::cerr << "[ERROR] Failed to encapsulate for decaps bench setup\n";
        EVP_PKEY_free(recipient);
        return {};
    }

    unsigned char decaps_secret[64];
    size_t ds_len;

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        ds_len = sizeof(decaps_secret);
        mlkem_decapsulate(recipient, ciphertext, ct_len,
                          decaps_secret, &ds_len);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        ds_len = sizeof(decaps_secret);

        auto t0 = Clock::now();
        bool ok = mlkem_decapsulate(recipient, ciphertext, ct_len,
                                    decaps_secret, &ds_len);
        auto t1 = Clock::now();

        if (!ok) {
            openssl_print_errors("ML-KEM decaps");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    EVP_PKEY_free(recipient);
    return durations;
}

std::vector<double> bench_mlkem_key_exchange(size_t warmup, size_t iterations) {
    unsigned char ciphertext[2048];
    unsigned char encaps_secret[64];
    unsigned char decaps_secret[64];
    size_t ct_len, enc_ss_len, dec_ss_len;

    // Warm-up
    for (size_t i = 0; i < warmup; ++i) {
        EVP_PKEY* k = generate_mlkem_key();
        ct_len     = sizeof(ciphertext);
        enc_ss_len = sizeof(encaps_secret);
        mlkem_encapsulate(k, ciphertext, &ct_len, encaps_secret, &enc_ss_len);
        dec_ss_len = sizeof(decaps_secret);
        mlkem_decapsulate(k, ciphertext, ct_len, decaps_secret, &dec_ss_len);
        EVP_PKEY_free(k);
    }

    // Measured
    std::vector<double> durations;
    durations.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = Clock::now();

        EVP_PKEY* k = generate_mlkem_key();
        ct_len     = sizeof(ciphertext);
        enc_ss_len = sizeof(encaps_secret);
        bool ok1 = mlkem_encapsulate(k, ciphertext, &ct_len,
                                     encaps_secret, &enc_ss_len);
        dec_ss_len = sizeof(decaps_secret);
        bool ok2 = mlkem_decapsulate(k, ciphertext, ct_len,
                                     decaps_secret, &dec_ss_len);

        auto t1 = Clock::now();

        EVP_PKEY_free(k);

        if (!ok1 || !ok2) {
            openssl_print_errors("ML-KEM key exchange");
            continue;
        }

        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        durations.push_back(us);
    }

    return durations;
}
