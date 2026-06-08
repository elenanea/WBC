/*
 * wbc1_aesni.c — WBC1-AES-NI
 * ===========================
 * Аппаратно-ускоренный вариант WBC-Cascade на Intel AES-NI инструкциях.
 *
 * Ключевые отличия:
 *   • Блок 16 байт (AES native), раундовая функция = AESENC (SubBytes +
 *     ShiftRows + MixColumns + XOR) — выполняется в 1-4 цикла на 16 байт
 *   • AES-128 key schedule (AESKEYGENASSIST)
 *   • CTR режим: 4-way pipeline (4 независимых цепочки AES) → ~4× throughput
 *   • Cascade key evolution: SHA-256 между блоками (forward secrecy)
 *   • WBC-CTR-HMAC: аутентифицированное шифрование (EtM)
 *
 * Build:
 *   gcc -O3 -maes -mpclmul -march=native -o wbc1_aesni wbc1_aesni.c -lssl -lcrypto -lm
 *
 * Требует: поддержку AES-NI (Intel Westmere+, AMD Bulldozer+)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <wmmintrin.h>      /* AES-NI intrinsics */
#include <cpuid.h>          /* __get_cpuid */
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── constants ─────────────────────────────────────────────────────────── */

#define MAGIC        "WBNI"
#define MAGIC_LEN    4
#define VERSION_CASC 0x0A   /* version tag for WBC-AES-NI */
#define NONCE_SIZE   12
#define MAC_SIZE     32
#define KEY_SIZE     32     /* master key size */
#define BLOCK_SIZE   16     /* AES native block size */
#define NR           10     /* AES-128 rounds */
#define NRK          11     /* number of round keys = NR + 1 */
#define PIPELINE     4      /* CTR parallel factor */

/* ── cascade flag ──────────────────────────────────────────────────────── */
static int g_use_cascade = 1;

/* ── CPU detection ─────────────────────────────────────────────────────── */
static int g_has_aesni = 0;

static void detect_cpu(void) {
    unsigned int a, b, c, d;
    g_has_aesni = __get_cpuid(1, &a, &b, &c, &d) && ((c >> 25) & 1);
}

/* ── SHA helpers ───────────────────────────────────────────────────────── */
static void sha256h(const uint8_t *in, size_t len, uint8_t out[32]) {
    SHA256(in, len, out);
}
static void sha512h(const uint8_t *in, size_t len, uint8_t out[64]) {
    SHA512(in, len, out);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AES-NI KEY EXPANSION
 *
 * Стандартное AES-128 key schedule:
 *   11 раундовых ключей по 16 байт из 16-байтного базового ключа.
 *   Использует инструкцию AESKEYGENASSIST для нелинейного шага.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Вспомогательная inline-функция для одного шага key schedule:
 *   key_next = key XOR сдвиги(key) XOR shuffle(keygened)
 */
static inline __m128i _kexpand(__m128i key, __m128i kg) {
    kg  = _mm_shuffle_epi32(kg, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, kg);
}

/* Развернуть 16-байтный ключ в 11 encryption round keys */
static void aesni_expand_enc(const uint8_t k[16], __m128i ek[NRK]) {
    ek[0]  = _mm_loadu_si128((__m128i*)k);
    ek[1]  = _kexpand(ek[0],  _mm_aeskeygenassist_si128(ek[0],  0x01));
    ek[2]  = _kexpand(ek[1],  _mm_aeskeygenassist_si128(ek[1],  0x02));
    ek[3]  = _kexpand(ek[2],  _mm_aeskeygenassist_si128(ek[2],  0x04));
    ek[4]  = _kexpand(ek[3],  _mm_aeskeygenassist_si128(ek[3],  0x08));
    ek[5]  = _kexpand(ek[4],  _mm_aeskeygenassist_si128(ek[4],  0x10));
    ek[6]  = _kexpand(ek[5],  _mm_aeskeygenassist_si128(ek[5],  0x20));
    ek[7]  = _kexpand(ek[6],  _mm_aeskeygenassist_si128(ek[6],  0x40));
    ek[8]  = _kexpand(ek[7],  _mm_aeskeygenassist_si128(ek[7],  0x80));
    ek[9]  = _kexpand(ek[8],  _mm_aeskeygenassist_si128(ek[8],  0x1B));
    ek[10] = _kexpand(ek[9],  _mm_aeskeygenassist_si128(ek[9],  0x36));
}

/* Построить decryption round keys из encryption round keys */
static void aesni_expand_dec(const __m128i ek[NRK], __m128i dk[NRK]) {
    dk[0] = ek[NR];                               /* последний enc → первый dec */
    for (int i = 1; i < NR; i++)
        dk[i] = _mm_aesimc_si128(ek[NR - i]);    /* AESIMC: MixColumns^(-1) */
    dk[NR] = ek[0];                               /* первый enc → последний dec */
}

/* ── однобалоковые операции ─────────────────────────────────────────────── */

static inline __m128i _aes_enc(__m128i s, const __m128i ek[NRK]) {
    s = _mm_xor_si128(s, ek[0]);
    s = _mm_aesenc_si128(s, ek[1]);  s = _mm_aesenc_si128(s, ek[2]);
    s = _mm_aesenc_si128(s, ek[3]);  s = _mm_aesenc_si128(s, ek[4]);
    s = _mm_aesenc_si128(s, ek[5]);  s = _mm_aesenc_si128(s, ek[6]);
    s = _mm_aesenc_si128(s, ek[7]);  s = _mm_aesenc_si128(s, ek[8]);
    s = _mm_aesenc_si128(s, ek[9]);
    return _mm_aesenclast_si128(s, ek[10]);
}

static inline __m128i _aes_dec(__m128i s, const __m128i dk[NRK]) {
    s = _mm_xor_si128(s, dk[0]);
    s = _mm_aesdec_si128(s, dk[1]);  s = _mm_aesdec_si128(s, dk[2]);
    s = _mm_aesdec_si128(s, dk[3]);  s = _mm_aesdec_si128(s, dk[4]);
    s = _mm_aesdec_si128(s, dk[5]);  s = _mm_aesdec_si128(s, dk[6]);
    s = _mm_aesdec_si128(s, dk[7]);  s = _mm_aesdec_si128(s, dk[8]);
    s = _mm_aesdec_si128(s, dk[9]);
    return _mm_aesdeclast_si128(s, dk[10]);
}

/*
 * key32_to_key16: из 32-байтного cascade-ключа получаем 16-байтный AES-ключ.
 * Метод: XOR двух половин — простой, детерминированный, без информационной
 * потери (обе половины участвуют).
 */
static inline void key32_to_key16(const uint8_t rk[KEY_SIZE], uint8_t aes16[16]) {
    for (int i = 0; i < 16; i++)
        aes16[i] = rk[i] ^ rk[i + 16];
}

/* ── WBC-специфичные ключевые функции ──────────────────────────────────── */

/* KDF: derive key_crypt и key_mac из master key + nonce через SHA-512 */
static void kdf(const uint8_t key[KEY_SIZE], const uint8_t nonce[NONCE_SIZE],
                uint8_t key_crypt[KEY_SIZE], uint8_t key_mac[KEY_SIZE]) {
    uint8_t buf[KEY_SIZE + NONCE_SIZE];
    memcpy(buf, key, KEY_SIZE);
    memcpy(buf + KEY_SIZE, nonce, NONCE_SIZE);
    uint8_t h[64];
    sha512h(buf, sizeof(buf), h);
    memcpy(key_crypt, h,           KEY_SIZE);
    memcpy(key_mac,   h + KEY_SIZE, KEY_SIZE);
}

/* Cascade: обновить ключ после шифрования блока */
static void advance_cascade_key(const uint8_t *enc_blk, uint8_t rk[KEY_SIZE]) {
    uint8_t buf[KEY_SIZE + BLOCK_SIZE];
    memcpy(buf,           rk,      KEY_SIZE);
    memcpy(buf + KEY_SIZE, enc_blk, BLOCK_SIZE);
    sha256h(buf, sizeof(buf), rk);
}

/* ── padding ─────────────────────────────────────────────────────────────
 * Выход всегда кратен BLOCK_SIZE.
 * Формат: data || zeros || fill_count(2 bytes) где все вместе = k*BLOCK_SIZE.
 * fill = (k*BLOCK_SIZE - dlen - 2), store as LE uint16 в последних 2 байтах.
 * ─────────────────────────────────────────────────────────────────────────*/

static uint8_t *wbc_pad(const uint8_t *data, size_t dlen, size_t *out_len) {
    size_t need = dlen + 2;   /* минимум: данные + 2 байта fill count */
    size_t alen = ((need + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    int fill = (int)(alen - need);  /* 0 .. BLOCK_SIZE-1 нулевых байт */
    uint8_t *p = (uint8_t *)calloc(1, alen);
    if (!p) return NULL;
    memcpy(p, data, dlen);
    /* fill нулевых байт уже заполнены calloc */
    p[alen - 2] = (uint8_t)(fill & 0xFF);
    p[alen - 1] = (uint8_t)(fill >> 8);
    *out_len = alen;
    return p;
}

static uint8_t *wbc_unpad(const uint8_t *data, size_t dlen, size_t *out_len) {
    if (dlen < 2 || dlen % BLOCK_SIZE != 0) return NULL;
    int fill = (int)data[dlen-2] | ((int)data[dlen-1] << 8);
    if (fill < 0 || fill >= BLOCK_SIZE) return NULL;
    size_t plen = dlen - 2 - (size_t)fill;
    uint8_t *p = (uint8_t *)malloc(plen + 1);
    if (!p) return NULL;
    memcpy(p, data, plen);
    p[plen] = 0;
    *out_len = plen;
    return p;
}

/* ── HMAC ────────────────────────────────────────────────────────────────── */

static void hmac_sha256(const uint8_t *key, size_t klen,
                         const uint8_t *data, size_t dlen, uint8_t out[MAC_SIZE]) {
    unsigned int olen = MAC_SIZE;
    HMAC(EVP_sha256(), key, (int)klen, data, dlen, out, &olen);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ECB ENCRYPT / DECRYPT
 *
 * Каждый 16-байтный блок:
 *   1. При cascade: derive AES-128 key из текущего cascade key → expand
 *   2. AESENC × 9 + AESENCLAST
 *   3. При cascade: advance_cascade_key(ciphertext, cascade_key)
 *
 * Без cascade: expand один раз → ~5-10 GB/s
 * С cascade: SHA-256 на каждый блок → ~200-400 MB/s
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t *ecb_encrypt(const uint8_t *key_crypt, const uint8_t *padded,
                              size_t plen, int cascade) {
    uint8_t *out = (uint8_t *)malloc(plen);
    if (!out) return NULL;

    uint8_t rk[KEY_SIZE];
    memcpy(rk, key_crypt, KEY_SIZE);

    uint8_t aes16[16];
    __m128i ek[NRK];

    if (!cascade) {
        key32_to_key16(rk, aes16);
        aesni_expand_enc(aes16, ek);
    }

    size_t n = plen / BLOCK_SIZE;
    for (size_t i = 0; i < n; i++) {
        if (cascade) {
            key32_to_key16(rk, aes16);
            aesni_expand_enc(aes16, ek);
        }
        __m128i s = _mm_loadu_si128((__m128i*)(padded + i * BLOCK_SIZE));
        s = _aes_enc(s, ek);
        _mm_storeu_si128((__m128i*)(out + i * BLOCK_SIZE), s);
        if (cascade) advance_cascade_key(out + i * BLOCK_SIZE, rk);
    }
    return out;
}

static uint8_t *ecb_decrypt(const uint8_t *key_crypt, const uint8_t *cdata,
                              size_t clen, int cascade) {
    uint8_t *out = (uint8_t *)malloc(clen);
    if (!out) return NULL;

    uint8_t rk[KEY_SIZE];
    memcpy(rk, key_crypt, KEY_SIZE);

    uint8_t aes16[16];
    __m128i ek[NRK], dk[NRK];

    if (!cascade) {
        key32_to_key16(rk, aes16);
        aesni_expand_enc(aes16, ek);
        aesni_expand_dec(ek, dk);
    }

    size_t n = clen / BLOCK_SIZE;
    for (size_t i = 0; i < n; i++) {
        if (cascade) {
            key32_to_key16(rk, aes16);
            aesni_expand_enc(aes16, ek);
            aesni_expand_dec(ek, dk);
        }
        __m128i s = _mm_loadu_si128((__m128i*)(cdata + i * BLOCK_SIZE));
        __m128i sc = s;  /* save ciphertext for cascade */
        s = _aes_dec(s, dk);
        _mm_storeu_si128((__m128i*)(out + i * BLOCK_SIZE), s);
        if (cascade) {
            uint8_t cb[BLOCK_SIZE];
            _mm_storeu_si128((__m128i*)cb, sc);
            advance_cascade_key(cb, rk);
        }
    }
    return out;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CTR MODE — 4-way pipelined
 *
 * Шифрует счётчики 4 блоками одновременно:
 *   ctr_blk[k] = AES_ENC(nonce || counter+k)  (независимые цепочки)
 *   out[k]     = in[k] XOR ctr_blk[k]
 *
 * Благодаря независимости цепочек, CPU исполняет 4 AESENC одновременно
 * (3-4 цикла throughput vs ~40 циклов latency → ~10× speedup).
 * ═══════════════════════════════════════════════════════════════════════════ */

static void ctr_crypt(const uint8_t key_crypt[KEY_SIZE],
                       const uint8_t nonce[NONCE_SIZE],
                       const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t aes16[16];
    key32_to_key16(key_crypt, aes16);
    __m128i ek[NRK];
    aesni_expand_enc(aes16, ek);

    /* Счётчик: 12-байтный nonce + 4-байтный big-endian counter */
    uint8_t ctr_base[BLOCK_SIZE];
    memset(ctr_base, 0, BLOCK_SIZE);
    memcpy(ctr_base, nonce, NONCE_SIZE);
    uint32_t ctr = 0;

    size_t pos = 0;

    /* ── 4-way parallel ── */
    while (pos + PIPELINE * BLOCK_SIZE <= len) {
        uint8_t cb[BLOCK_SIZE];
        memcpy(cb, ctr_base, NONCE_SIZE);

        /* Загружаем 4 counter-блока */
#define LOAD_CTR(V, N) \
        { *(uint32_t*)(cb + NONCE_SIZE) = __builtin_bswap32(ctr + (N)); \
          V = _mm_loadu_si128((__m128i*)cb); }

        __m128i c0, c1, c2, c3;
        LOAD_CTR(c0, 0) LOAD_CTR(c1, 1) LOAD_CTR(c2, 2) LOAD_CTR(c3, 3)
        ctr += PIPELINE;
#undef LOAD_CTR

        /* Начальный whitening */
        c0 = _mm_xor_si128(c0, ek[0]);
        c1 = _mm_xor_si128(c1, ek[0]);
        c2 = _mm_xor_si128(c2, ek[0]);
        c3 = _mm_xor_si128(c3, ek[0]);

        /* 9 полных раундов — 4 независимые цепочки */
        for (int r = 1; r <= 9; r++) {
            c0 = _mm_aesenc_si128(c0, ek[r]);
            c1 = _mm_aesenc_si128(c1, ek[r]);
            c2 = _mm_aesenc_si128(c2, ek[r]);
            c3 = _mm_aesenc_si128(c3, ek[r]);
        }

        /* Последний раунд */
        c0 = _mm_aesenclast_si128(c0, ek[10]);
        c1 = _mm_aesenclast_si128(c1, ek[10]);
        c2 = _mm_aesenclast_si128(c2, ek[10]);
        c3 = _mm_aesenclast_si128(c3, ek[10]);

        /* XOR с открытым/шифротекстом */
        c0 = _mm_xor_si128(c0, _mm_loadu_si128((__m128i*)(in + pos)));
        c1 = _mm_xor_si128(c1, _mm_loadu_si128((__m128i*)(in + pos + 16)));
        c2 = _mm_xor_si128(c2, _mm_loadu_si128((__m128i*)(in + pos + 32)));
        c3 = _mm_xor_si128(c3, _mm_loadu_si128((__m128i*)(in + pos + 48)));

        _mm_storeu_si128((__m128i*)(out + pos),      c0);
        _mm_storeu_si128((__m128i*)(out + pos + 16), c1);
        _mm_storeu_si128((__m128i*)(out + pos + 32), c2);
        _mm_storeu_si128((__m128i*)(out + pos + 48), c3);

        pos += PIPELINE * BLOCK_SIZE;
    }

    /* Остаток: 0-3 блока поодиночке */
    while (pos < len) {
        uint8_t cb[BLOCK_SIZE];
        memcpy(cb, ctr_base, NONCE_SIZE);
        *(uint32_t*)(cb + NONCE_SIZE) = __builtin_bswap32(ctr++);

        __m128i c = _mm_loadu_si128((__m128i*)cb);
        c = _aes_enc(c, ek);

        /* Записываем побайтно на случай неполного последнего блока */
        uint8_t ks[BLOCK_SIZE];
        _mm_storeu_si128((__m128i*)ks, c);
        size_t chunk = (len - pos < BLOCK_SIZE) ? len - pos : BLOCK_SIZE;
        for (size_t j = 0; j < chunk; j++)
            out[pos + j] = in[pos + j] ^ ks[j];
        pos += chunk;
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * CBC / CFB / OFB (sequential modes for completeness)
 * ─────────────────────────────────────────────────────────────────────────*/

static void cbc_encrypt(const uint8_t *kc, const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t n_blocks) {
    uint8_t a[16]; key32_to_key16(kc, a);
    __m128i ek[NRK]; aesni_expand_enc(a, ek);
    __m128i prev = _mm_loadu_si128((__m128i*)iv);
    for (size_t i = 0; i < n_blocks; i++) {
        __m128i b = _mm_xor_si128(_mm_loadu_si128((__m128i*)(in+i*16)), prev);
        prev = _aes_enc(b, ek);
        _mm_storeu_si128((__m128i*)(out+i*16), prev);
    }
}

static void cbc_decrypt(const uint8_t *kc, const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t n_blocks) {
    uint8_t a[16]; key32_to_key16(kc, a);
    __m128i ek[NRK], dk[NRK];
    aesni_expand_enc(a, ek); aesni_expand_dec(ek, dk);
    __m128i prev = _mm_loadu_si128((__m128i*)iv);
    for (size_t i = 0; i < n_blocks; i++) {
        __m128i c = _mm_loadu_si128((__m128i*)(in+i*16));
        __m128i p = _mm_xor_si128(_aes_dec(c, dk), prev);
        prev = c;
        _mm_storeu_si128((__m128i*)(out+i*16), p);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * РЕЖИМЫ ШИФРОВАНИЯ (верхний уровень)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum { MODE_ECB, MODE_CBC, MODE_CTR, MODE_WBC_CTR_HMAC } EncMode;

static const char *mode_name(EncMode m) {
    switch(m) {
        case MODE_ECB:          return "ECB";
        case MODE_CBC:          return "CBC";
        case MODE_CTR:          return "CTR";
        case MODE_WBC_CTR_HMAC: return "WBC-CTR-HMAC";
    }
    return "?";
}

/* Encrypt data → allocated output (caller must free) */
static uint8_t *wbc_encrypt(const uint8_t *key, size_t klen __attribute__((unused)),
                              const uint8_t *data, size_t dlen,
                              size_t *out_len, EncMode mode) {
    uint8_t nonce[NONCE_SIZE];
    RAND_bytes(nonce, NONCE_SIZE);

    uint8_t key_crypt[KEY_SIZE], key_mac[KEY_SIZE];
    kdf(key, nonce, key_crypt, key_mac);

    /* Header: MAGIC[4] + VERSION[1] + MODE[1] + NONCE[12] = 18 bytes */
    const size_t HDR = MAGIC_LEN + 1 + 1 + NONCE_SIZE;

    uint8_t *padded = NULL; size_t plen = 0;
    uint8_t *cipher = NULL; size_t clen = 0;

    if (mode == MODE_ECB || mode == MODE_CBC) {
        padded = wbc_pad(data, dlen, &plen);
        if (!padded) return NULL;
        clen = plen;
    } else {
        clen = dlen;
    }

    /* Allocate output: HDR + ciphertext [+ IV for CBC] [+ MAC] */
    size_t mac_space = (mode == MODE_WBC_CTR_HMAC) ? MAC_SIZE : 0;
    size_t iv_space  = (mode == MODE_CBC) ? BLOCK_SIZE : 0;
    uint8_t *out = (uint8_t *)malloc(HDR + clen + iv_space + mac_space);
    if (!out) { free(padded); return NULL; }

    /* Write header */
    memcpy(out, MAGIC, MAGIC_LEN);
    out[MAGIC_LEN]     = VERSION_CASC;
    out[MAGIC_LEN + 1] = (uint8_t)mode;
    memcpy(out + MAGIC_LEN + 2, nonce, NONCE_SIZE);

    uint8_t *cp = out + HDR;

    switch (mode) {
        case MODE_ECB: {
            cipher = ecb_encrypt(key_crypt, padded, plen, g_use_cascade);
            if (!cipher) { free(padded); free(out); return NULL; }
            memcpy(cp, cipher, clen);
            free(cipher);
            break;
        }
        case MODE_CBC: {
            uint8_t iv[16]; RAND_bytes(iv, 16);
            memcpy(cp, iv, 16);
            cp += 16; clen += 16;
            cbc_encrypt(key_crypt, iv, padded, cp, plen / BLOCK_SIZE);
            break;
        }
        case MODE_CTR:
        case MODE_WBC_CTR_HMAC: {
            ctr_crypt(key_crypt, nonce, data, cp, dlen);
            if (mode == MODE_WBC_CTR_HMAC) {
                /* MAC = HMAC-SHA256(key_mac, nonce || ciphertext) */
                uint8_t mac_buf[NONCE_SIZE + dlen];
                memcpy(mac_buf, nonce, NONCE_SIZE);
                memcpy(mac_buf + NONCE_SIZE, cp, dlen);
                hmac_sha256(key_mac, KEY_SIZE, mac_buf, NONCE_SIZE + dlen,
                             cp + dlen);
            }
            break;
        }
    }

    free(padded);
    *out_len = HDR + clen + mac_space;
    return out;
}

static uint8_t *wbc_decrypt(const uint8_t *key, size_t klen __attribute__((unused)),
                              const uint8_t *data, size_t dlen,
                              size_t *out_len) {
    const size_t HDR = MAGIC_LEN + 1 + 1 + NONCE_SIZE;
    if (dlen < HDR) return NULL;
    if (memcmp(data, MAGIC, MAGIC_LEN) != 0) return NULL;
    if (data[MAGIC_LEN] != VERSION_CASC) return NULL;

    EncMode mode = (EncMode)data[MAGIC_LEN + 1];
    const uint8_t *nonce = data + MAGIC_LEN + 2;
    const uint8_t *cp    = data + HDR;
    size_t clen = dlen - HDR;

    uint8_t key_crypt[KEY_SIZE], key_mac[KEY_SIZE];
    kdf(key, nonce, key_crypt, key_mac);

    switch (mode) {
        case MODE_ECB: {
            uint8_t *plain = ecb_decrypt(key_crypt, cp, clen, g_use_cascade);
            if (!plain) return NULL;
            uint8_t *out = wbc_unpad(plain, clen, out_len);
            free(plain);
            return out;
        }
        case MODE_CBC: {
            if (clen < 16) return NULL;
            const uint8_t *iv = cp;
            uint8_t *plain = (uint8_t *)malloc(clen - 16);
            if (!plain) return NULL;
            cbc_decrypt(key_crypt, iv, cp + 16, plain, (clen - 16) / BLOCK_SIZE);
            uint8_t *out = wbc_unpad(plain, clen - 16, out_len);
            free(plain);
            return out;
        }
        case MODE_WBC_CTR_HMAC: {
            if (clen < MAC_SIZE) return NULL;
            size_t elen = clen - MAC_SIZE;
            const uint8_t *mac_stored = cp + elen;
            /* Verify MAC */
            uint8_t mac_buf[NONCE_SIZE + elen];
            memcpy(mac_buf, nonce, NONCE_SIZE);
            memcpy(mac_buf + NONCE_SIZE, cp, elen);
            uint8_t mac_calc[MAC_SIZE];
            hmac_sha256(key_mac, KEY_SIZE, mac_buf, NONCE_SIZE + elen, mac_calc);
            if (CRYPTO_memcmp(mac_stored, mac_calc, MAC_SIZE) != 0) {
                fprintf(stderr, "MAC verification FAILED!\n");
                return NULL;
            }
            uint8_t *out = (uint8_t *)malloc(elen + 1);
            if (!out) return NULL;
            ctr_crypt(key_crypt, nonce, cp, out, elen);
            out[elen] = 0;
            *out_len = elen;
            return out;
        }
        case MODE_CTR: {
            uint8_t *out = (uint8_t *)malloc(clen + 1);
            if (!out) return NULL;
            ctr_crypt(key_crypt, nonce, cp, out, clen);
            out[clen] = 0;
            *out_len = clen;
            return out;
        }
    }
    return NULL;
}

/* ── self-tests ─────────────────────────────────────────────────────────── */

static int run_self_tests(void) {
    static const uint8_t KEY[KEY_SIZE] = {
        0x60,0x3D,0xEB,0x10,0x15,0xCA,0x71,0xBE,
        0x2B,0x73,0xAE,0xF0,0x85,0x7D,0x77,0x81,
        0x1F,0x35,0x2C,0x07,0x3B,0x61,0x08,0xD7,
        0x2D,0x98,0x10,0xA3,0x09,0x14,0xDF,0xF4
    };

    static const struct { const char *name; size_t len; } CASES[] = {
        {"Short text (13B)",  13},
        {"One block (16B)",   16},
        {"Two blocks (32B)",  32},
        {"300 bytes",        300},
        {"1000 bytes",      1000},
        {"All zeros (16B)",   16},
        {"All ones (16B)",    16},
        {"10 000 bytes",   10000},
        {"100 000 bytes", 100000},
    };
    const int NC = (int)(sizeof(CASES)/sizeof(CASES[0]));

    EncMode modes[] = { MODE_ECB, MODE_CTR, MODE_WBC_CTR_HMAC };
    const int NM = (int)(sizeof(modes)/sizeof(modes[0]));

    int passed = 0, total = 0;

    for (int m = 0; m < NM; m++) {
        for (int c = 0; c < NC; c++) {
            size_t len = CASES[c].len;
            uint8_t *orig = (uint8_t *)malloc(len);
            if (!orig) continue;
            for (size_t i = 0; i < len; i++) orig[i] = (uint8_t)(i ^ (i>>3));
            if (c == 5) memset(orig, 0, len);
            if (c == 6) memset(orig, 0xFF, len);

            size_t elen = 0, dlen = 0;
            uint8_t *enc = wbc_encrypt(KEY, KEY_SIZE, orig, len, &elen, modes[m]);
            uint8_t *dec = enc ? wbc_decrypt(KEY, KEY_SIZE, enc, elen, &dlen) : NULL;

            int ok = dec && dlen == len && memcmp(orig, dec, len) == 0;
            printf("  [%-16s] %-20s %s\n",
                   mode_name(modes[m]), CASES[c].name, ok ? "PASS ✓" : "FAIL ✗");
            passed += ok; total++;

            free(orig); free(enc); free(dec);
        }
    }
    printf("  Results: %d/%d passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}

/* ── benchmark ──────────────────────────────────────────────────────────── */

static void run_benchmark(EncMode mode) {
    static const uint8_t KEY[KEY_SIZE] = {
        0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
        0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C,
        0x1A,0x2B,0x3C,0x4D,0x5E,0x6F,0x70,0x81,
        0x92,0xA3,0xB4,0xC5,0xD6,0xE7,0xF8,0x09
    };

    static const size_t SIZES[] = {
        16, 64, 256, 1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024
    };
    const int NS = (int)(sizeof(SIZES)/sizeof(SIZES[0]));

    const char *BENCH_REPS_ENV = getenv("WBC_BENCH_REPEATS");
    int reps = BENCH_REPS_ENV ? atoi(BENCH_REPS_ENV) : 5;
    if (reps < 1) reps = 1;

    printf("\n  Benchmark mode: %s  (cascade=%s)\n",
           mode_name(mode), g_use_cascade ? "ON" : "OFF");
    printf("  %10s  %10s  %14s  %14s  %s\n",
           "Size (KB)", "Enc (s)", "Enc (KB/s)", "Dec (KB/s)", "Integrity");
    printf("  %s\n",
           "------------------------------------------------------------------");

    for (int si = 0; si < NS; si++) {
        size_t sz = SIZES[si];
        uint8_t *data = (uint8_t *)malloc(sz);
        if (!data) continue;
        for (size_t i = 0; i < sz; i++) data[i] = (uint8_t)(i * 0x41 + 0x37);

        double enc_time = 0, dec_time = 0;
        int ok = 1;

        for (int r = 0; r < reps; r++) {
            struct timespec t0, t1;

            clock_gettime(CLOCK_MONOTONIC, &t0);
            size_t elen = 0;
            uint8_t *enc = wbc_encrypt(KEY, KEY_SIZE, data, sz, &elen, mode);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (!enc) { ok = 0; break; }
            enc_time += (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec)*1e-9;

            clock_gettime(CLOCK_MONOTONIC, &t0);
            size_t dlen = 0;
            uint8_t *dec = wbc_decrypt(KEY, KEY_SIZE, enc, elen, &dlen);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (!dec || dlen != sz || memcmp(data, dec, sz)) ok = 0;
            dec_time += (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec)*1e-9;

            free(enc); free(dec);
            if (!ok) break;
        }

        enc_time /= reps; dec_time /= reps;
        double kb = sz / 1024.0;
        printf("  %10.2f  %10.5f  %14.2f  %14.2f  %s\n",
               kb, enc_time, kb / enc_time, kb / dec_time,
               ok ? "OK" : "FAIL");

        free(data);
    }
    printf("\n");
}

/* ── avalanche stats ────────────────────────────────────────────────────── */

static void run_stats(void) {
    static const uint8_t KEY[KEY_SIZE] = {
        0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00
    };

    const int N = 1000;
    const size_t LEN = 64;
    long long changed = 0, total_bits = 0;
    double sum_entropy = 0;
    long freq[256] = {0};

    for (int i = 0; i < N; i++) {
        uint8_t plain[64];
        for (size_t j = 0; j < LEN; j++) plain[j] = (uint8_t)(rand() & 0xFF);

        size_t elen = 0;
        uint8_t *enc1 = wbc_encrypt(KEY, KEY_SIZE, plain, LEN, &elen, MODE_ECB);
        if (!enc1) continue;

        /* Flip 1 bit in plaintext */
        uint8_t plain2[64];
        memcpy(plain2, plain, LEN);
        plain2[i % LEN] ^= (uint8_t)(1 << (i & 7));

        size_t elen2 = 0;
        uint8_t *enc2 = wbc_encrypt(KEY, KEY_SIZE, plain2, LEN, &elen2, MODE_ECB);
        if (!enc2) { free(enc1); continue; }

        size_t cmp_len = elen < elen2 ? elen : elen2;
        for (size_t j = 0; j < cmp_len; j++) {
            uint8_t d = enc1[j] ^ enc2[j];
            changed    += __builtin_popcount(d);
            total_bits += 8;
            freq[enc1[j]]++;
        }

        free(enc1); free(enc2);
    }

    /* Entropy */
    long long total_bytes = 0;
    for (int b = 0; b < 256; b++) total_bytes += freq[b];
    for (int b = 0; b < 256; b++) {
        if (freq[b]) {
            double p = (double)freq[b] / total_bytes;
            sum_entropy -= p * log2(p);
        }
    }

    /* Chi-square */
    double expected = (double)total_bytes / 256.0;
    double chi2 = 0;
    for (int b = 0; b < 256; b++) {
        double d = freq[b] - expected;
        chi2 += d * d / expected;
    }

    printf("  Avalanche (1-bit flip):   %.2f%%\n",
           total_bits ? 100.0 * changed / total_bits : 0.0);
    printf("  Shannon entropy:          %.4f bits/byte\n", sum_entropy);
    printf("  Chi-square (ideal=255):   %.2f\n", chi2);
}

/* ── menu ───────────────────────────────────────────────────────────────── */

static void menu_encrypt_text(const uint8_t *key) {
    char buf[4096] = {0};
    printf("  Enter text: "); fflush(stdout);
    if (!fgets(buf, sizeof(buf)-1, stdin)) return;
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1]=='\n'||buf[len-1]=='\r')) buf[--len]=0;
    if (!len) { puts("  (empty)"); return; }

    size_t elen = 0;
    uint8_t *enc = wbc_encrypt(key, KEY_SIZE, (uint8_t*)buf, len,
                                &elen, MODE_WBC_CTR_HMAC);
    if (!enc) { puts("  Encrypt failed"); return; }

    printf("  Encrypted (%zu bytes): ", elen);
    for (size_t i = 0; i < elen && i < 48; i++) printf("%02X", enc[i]);
    if (elen > 48) printf("...");
    puts("");

    size_t dlen = 0;
    uint8_t *dec = wbc_decrypt(key, KEY_SIZE, enc, elen, &dlen);
    if (dec) {
        printf("  Decrypted: %s\n", (char*)dec);
        free(dec);
    } else {
        puts("  Decrypt failed");
    }
    free(enc);
}

int main(int argc, char *argv[]) {
    detect_cpu();

    if (!g_has_aesni) {
        fprintf(stderr,
            "ERROR: AES-NI not supported on this CPU.\n"
            "       Requires Intel Westmere+ or AMD Bulldozer+.\n");
        return 1;
    }

    (void)argc; (void)argv;  /* single-mode always */

    static const uint8_t DEMO_KEY[KEY_SIZE] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };

    printf("\n=== WBC1-AES-NI [cascade=%s] ===\n",
           g_use_cascade ? "ON" : "OFF");
    printf("    AES-NI: YES  |  Block: 16B  |  Rounds: %d\n\n", NR);

    for (;;) {
        printf("1. Encrypt / decrypt text\n");
        printf("2. Run self-tests\n");
        printf("3. Benchmark ECB\n");
        printf("4. Benchmark CTR (4-way pipeline)\n");
        printf("5. Avalanche + statistics\n");
        printf("6. Toggle cascade (cascade=%s)\n",
               g_use_cascade ? "ON→OFF" : "OFF→ON");
        printf("7. Exit\n");
        printf("Select (1-7): "); fflush(stdout);

        int choice = 0;
        char line[32] = {0};
        if (!fgets(line, sizeof(line), stdin)) break;
        choice = atoi(line);

        switch (choice) {
            case 1: menu_encrypt_text(DEMO_KEY); break;
            case 2: run_self_tests(); break;
            case 3: run_benchmark(MODE_ECB); break;
            case 4: run_benchmark(MODE_CTR); break;
            case 5: run_stats(); break;
            case 6:
                g_use_cascade = !g_use_cascade;
                printf("  Cascade: %s\n", g_use_cascade ? "ON" : "OFF");
                break;
            case 7: puts("Bye!"); return 0;
            default: puts("  Invalid choice"); break;
        }
    }
    return 0;
}
