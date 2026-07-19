/*
 * benchmark.cpp
 *
 * Experiment 5: Secure IPC Simulation
 * Process Isolation / Secure Messaging
 *
 * Project: Post-Quantum Ready XR Native Operating System
 */

#include "benchmark.h"
#include <openssl/core_names.h>
#include <openssl/params.h>

using Clock = BenchClock;

// ============================================================================
// Cryptographic Helpers
// ============================================================================

static EVP_PKEY* generate_ec_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>("prime256v1"), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY* generate_mlkem_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr);
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static bool ecdh_derive(EVP_PKEY* our_key, EVP_PKEY* peer_key, unsigned char* secret, size_t* secret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(our_key, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_derive_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    EVP_PKEY_CTX_free(ctx);
    return true;
}

static bool mlkem_encapsulate(EVP_PKEY* peer_key, unsigned char* ct, size_t* ct_len, unsigned char* secret, size_t* secret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(peer_key, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    if (EVP_PKEY_encapsulate(ctx, ct, ct_len, secret, secret_len) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    EVP_PKEY_CTX_free(ctx);
    return true;
}

static bool mlkem_decapsulate(EVP_PKEY* our_key, const unsigned char* ct, size_t ct_len, unsigned char* secret, size_t* secret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(our_key, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    if (EVP_PKEY_decapsulate(ctx, secret, secret_len, ct, ct_len) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    EVP_PKEY_CTX_free(ctx);
    return true;
}

// Very simple KDF using SHA-256
static bool derive_aes_key(const unsigned char* secret, size_t secret_len, unsigned char* aes_key_32b) {
    unsigned int md_len = 0;
    if (!EVP_Digest(secret, secret_len, aes_key_32b, &md_len, EVP_sha256(), nullptr)) return false;
    return md_len == 32;
}

static bool aes_gcm_encrypt(const unsigned char* key, const unsigned char* iv, size_t iv_len,
                            const unsigned char* pt, size_t pt_len,
                            unsigned char* ct, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) goto err;
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto err;
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return true;
err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

static bool aes_gcm_decrypt(const unsigned char* key, const unsigned char* iv, size_t iv_len,
                            const unsigned char* ct, size_t ct_len, const unsigned char* tag,
                            unsigned char* pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr) != 1) goto err;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) goto err;
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) != 1) goto err;
    
    // Final will return 1 if tag matches, <= 0 otherwise
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) <= 0) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return true;
err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

// ============================================================================
// Secure IPC Benchmarks
// ============================================================================

std::vector<double> bench_classical_ipc(size_t payload_size, size_t warmup, size_t iterations) {
    std::vector<double> durations;
    durations.reserve(iterations);

    std::vector<unsigned char> payload(payload_size, 0x42);
    std::vector<unsigned char> ct_buf(payload_size);
    std::vector<unsigned char> dec_buf(payload_size);
    unsigned char tag[16];
    unsigned char iv[12] = {0}; // Fixed IV for benchmark

    for (size_t i = 0; i < warmup + iterations; ++i) {
        auto t0 = Clock::now();

        // 1. Key generation (Alice & Bob)
        EVP_PKEY* alice_key = generate_ec_key();
        EVP_PKEY* bob_key = generate_ec_key();
        if (!alice_key || !bob_key) continue;

        // 2. Key derivation (Bob derives secret & encrypts)
        unsigned char bob_secret[256];
        size_t bob_sec_len = sizeof(bob_secret);
        ecdh_derive(bob_key, alice_key, bob_secret, &bob_sec_len);

        unsigned char bob_aes_key[32];
        derive_aes_key(bob_secret, bob_sec_len, bob_aes_key);

        aes_gcm_encrypt(bob_aes_key, iv, sizeof(iv), payload.data(), payload.size(), ct_buf.data(), tag);

        // 3. Key derivation (Alice derives secret & decrypts)
        unsigned char alice_secret[256];
        size_t alice_sec_len = sizeof(alice_secret);
        ecdh_derive(alice_key, bob_key, alice_secret, &alice_sec_len);

        unsigned char alice_aes_key[32];
        derive_aes_key(alice_secret, alice_sec_len, alice_aes_key);

        bool dec_ok = aes_gcm_decrypt(alice_aes_key, iv, sizeof(iv), ct_buf.data(), ct_buf.size(), tag, dec_buf.data());

        auto t1 = Clock::now();

        if (!dec_ok) {
            std::cerr << "[ERROR] Classical IPC Decryption failed\n";
        } else if (i >= warmup) {
            durations.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        }

        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
    }
    return durations;
}

std::vector<double> bench_pq_ipc(size_t payload_size, size_t warmup, size_t iterations) {
    std::vector<double> durations;
    durations.reserve(iterations);

    std::vector<unsigned char> payload(payload_size, 0x42);
    std::vector<unsigned char> ct_buf(payload_size);
    std::vector<unsigned char> dec_buf(payload_size);
    unsigned char tag[16];
    unsigned char iv[12] = {0};

    for (size_t i = 0; i < warmup + iterations; ++i) {
        auto t0 = Clock::now();

        // 1. Key generation (Alice only for KEM)
        EVP_PKEY* alice_key = generate_mlkem_key();
        if (!alice_key) continue;

        // 2. Encapsulation (Bob encapsulates & encrypts)
        unsigned char kem_ct[4096];
        size_t kem_ct_len = sizeof(kem_ct);
        unsigned char bob_secret[256];
        size_t bob_sec_len = sizeof(bob_secret);
        mlkem_encapsulate(alice_key, kem_ct, &kem_ct_len, bob_secret, &bob_sec_len);

        unsigned char bob_aes_key[32];
        derive_aes_key(bob_secret, bob_sec_len, bob_aes_key);

        aes_gcm_encrypt(bob_aes_key, iv, sizeof(iv), payload.data(), payload.size(), ct_buf.data(), tag);

        // 3. Decapsulation (Alice decapsulates & decrypts)
        unsigned char alice_secret[256];
        size_t alice_sec_len = sizeof(alice_secret);
        mlkem_decapsulate(alice_key, kem_ct, kem_ct_len, alice_secret, &alice_sec_len);

        unsigned char alice_aes_key[32];
        derive_aes_key(alice_secret, alice_sec_len, alice_aes_key);

        bool dec_ok = aes_gcm_decrypt(alice_aes_key, iv, sizeof(iv), ct_buf.data(), ct_buf.size(), tag, dec_buf.data());

        auto t1 = Clock::now();

        if (!dec_ok) {
            std::cerr << "[ERROR] PQ IPC Decryption failed\n";
        } else if (i >= warmup) {
            durations.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        }

        EVP_PKEY_free(alice_key);
    }
    return durations;
}
