/* prim: what each libcrypto primitive the Goose server uses allocates,
   counted through CRYPTO_set_mem_functions, with its algorithms fetched once
   beforehand as shim/server.c fetches them. One line per primitive:

     held       bytes held once it is set up, as a connection keeps it
     used       bytes held after one use: a 16 KB record, a hash, a derive
     peak       the most held at any point from setup through use
     freed      bytes still held after it is freed (0 unless it leaks)

   Primitives a connection doesn't keep (HMAC, HKDF, key exchange) are made
   and freed inside their use, so for them held is 0 and peak is all. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

static size_t now, peak;
static void *m(size_t n, const char *f, int l) {
    (void)f, (void)l;
    size_t *p = malloc(n + 16);
    if (!p) return NULL;
    *p = n;
    now += n;
    if (now > peak) peak = now;
    return (char *)p + 16;
}
static void *r(void *q, size_t n, const char *f, int l) {
    if (!q) return m(n, f, l);
    size_t *p = (size_t *)((char *)q - 16), old = *p;
    p = realloc(p, n + 16);
    if (!p) return NULL;
    *p = n;
    now = now - old + n;
    if (now > peak) peak = now;
    return (char *)p + 16;
}
static void fr(void *q, const char *f, int l) {
    (void)f, (void)l;
    if (!q) return;
    size_t *p = (size_t *)((char *)q - 16);
    now -= *p;
    free(p);
}

static size_t base;
static void start(void) { base = peak = now; }
static void report(const char *name, size_t held, size_t used) {
    printf("prim=%s held=%zu used=%zu peak=%zu freed=%zu\n", name, held - base, used - base, peak - base, now - base);
}
static void die(const char *what) {
    fprintf(stderr, "prim: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static uint8_t buf[16384 + 32], key[32], iv[12], tag[16];

static void aead(const char *name, EVP_CIPHER *c) {
    start();
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    if (!x || EVP_CipherInit_ex2(x, c, key, NULL, 1, NULL) != 1) die(name);
    size_t held = now;
    int n = 0;
    if (EVP_CipherInit_ex2(x, NULL, NULL, iv, 1, NULL) != 1 || EVP_EncryptUpdate(x, NULL, &n, buf, 5) != 1 ||
        EVP_EncryptUpdate(x, buf, &n, buf, 16384) != 1 || EVP_EncryptFinal_ex(x, buf + n, &n) != 1 ||
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1)
        die(name);
    size_t used = now;
    EVP_CIPHER_CTX_free(x);
    report(name, held, used);
}

static void hash(const char *name, EVP_MD *md) {
    start();
    EVP_MD_CTX *x = EVP_MD_CTX_new();
    if (!x || EVP_DigestInit_ex2(x, md, NULL) != 1) die(name);
    size_t held = now;
    EVP_MD_CTX *copy = EVP_MD_CTX_new();
    unsigned int n = 0;
    if (EVP_DigestUpdate(x, buf, 4096) != 1 || !copy || EVP_MD_CTX_copy_ex(copy, x) != 1 ||
        EVP_DigestFinal_ex(copy, buf, &n) != 1)
        die(name);
    EVP_MD_CTX_free(copy);
    size_t used = now;
    EVP_MD_CTX_free(x);
    report(name, held, used);
}

static void hmac(void) {
    start();
    size_t n = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, buf, 32, buf + 64, 64, &n)) die("hmac");
    report("hmac-sha256", base, now);
}

static void hkdf(EVP_KDF *kdf) {
    start();
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 32),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, buf, 20),
        OSSL_PARAM_construct_end(),
    };
    EVP_KDF_CTX *x = EVP_KDF_CTX_new(kdf);
    if (!x || EVP_KDF_derive(x, buf + 64, 32, params) != 1) die("hkdf");
    EVP_KDF_CTX_free(x);
    report("hkdf-expand-sha256", base, now);
}

/* A peer's public key, made once outside the count. */
static EVP_PKEY *peer_x25519, *peer_p256;
static uint8_t peer_ek[1184];

static void x25519(void) {
    start();
    EVP_PKEY *ours = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    uint8_t ss[32];
    size_t n = 32;
    EVP_PKEY_CTX *x = ours ? EVP_PKEY_CTX_new_from_pkey(NULL, ours, NULL) : NULL;
    if (!x || EVP_PKEY_derive_init(x) != 1 || EVP_PKEY_derive_set_peer_ex(x, peer_x25519, 1) != 1 ||
        EVP_PKEY_derive(x, ss, &n) != 1)
        die("x25519");
    EVP_PKEY_CTX_free(x);
    EVP_PKEY_free(ours);
    report("x25519", base, now);
}

static void p256(void) {
    start();
    EVP_PKEY *ours = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    uint8_t ss[32];
    size_t n = 32;
    EVP_PKEY_CTX *x = ours ? EVP_PKEY_CTX_new_from_pkey(NULL, ours, NULL) : NULL;
    if (!x || EVP_PKEY_derive_init(x) != 1 || EVP_PKEY_derive_set_peer_ex(x, peer_p256, 1) != 1 ||
        EVP_PKEY_derive(x, ss, &n) != 1)
        die("p256");
    EVP_PKEY_CTX_free(x);
    EVP_PKEY_free(ours);
    report("p256-ecdh", base, now);
}

static void mlkem(void) {
    start();
    EVP_PKEY *ek = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-KEM-768", NULL, peer_ek, sizeof peer_ek);
    EVP_PKEY_CTX *x = ek ? EVP_PKEY_CTX_new_from_pkey(NULL, ek, NULL) : NULL;
    uint8_t ct[1088], ss[32];
    size_t ctl = sizeof ct, sl = sizeof ss;
    if (!x || EVP_PKEY_encapsulate_init(x, NULL) != 1 || EVP_PKEY_encapsulate(x, ct, &ctl, ss, &sl) != 1)
        die("ml-kem-768");
    EVP_PKEY_CTX_free(x);
    EVP_PKEY_free(ek);
    report("ml-kem-768-encapsulate", base, now);
}

int main(void) {
    if (!CRYPTO_set_mem_functions(m, r, fr)) die("OpenSSL allocated first");
    EVP_CIPHER *aes128 = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    EVP_CIPHER *aes256 = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    EVP_CIPHER *chacha = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
    EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL), *sha384 = EVP_MD_fetch(NULL, "SHA384", NULL);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!aes128 || !aes256 || !chacha || !sha256 || !sha384 || !kdf) die("fetch");
    peer_x25519 = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    peer_p256 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *dk = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    size_t ekl = sizeof peer_ek;
    if (!peer_x25519 || !peer_p256 || !dk || EVP_PKEY_get_raw_public_key(dk, peer_ek, &ekl) != 1) die("peers");
    printf("# %s; after the fetches: %zu bytes held\n", OpenSSL_version(OPENSSL_VERSION), now);
    /* Each twice, so that a cache filled on first use shows as the first
       run's alone. */
    for (int i = 0; i < 2; i++) {
        aead("aes-128-gcm", aes128);
        aead("aes-256-gcm", aes256);
        aead("chacha20-poly1305", chacha);
        hash("sha256", sha256);
        hash("sha384", sha384);
        hmac();
        hkdf(kdf);
        x25519();
        p256();
        mlkem();
    }
    return 0;
}
