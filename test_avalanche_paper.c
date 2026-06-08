/*
 * test_avalanche_paper.c
 *
 * Порівняння лавинного ефекту WBC1 (encrypt_block) та AES-128-ECB
 * за формулами теорії SAC (Strict Avalanche Criterion):
 *
 *   Формула (2): W(a_j^{e_i}) = Σ_j a_j^{e_i}
 *                де a_j^{e_i}(x) = f_j(x) ⊕ f_j(x ⊕ e_i)
 *                (кількість вихідних бітів, що змінились при фліпі біту e_i)
 *
 *   Формула (1): (1/2^n) * Σ_j W(a_j^{e_i}) = n/2
 *                (ідеал: у середньому половина вихідних бітів змінюється)
 *
 *   Формула (3): K_avalanche(i) = (1 / (n·2^n)) * Σ_j W(a_j^{e_i}) = 1/2
 *                (нормований крітерій SAC; = 1/2 при ідеальній дифузії)
 *
 * Практична оцінка (n великий → не можна перебрати всі 2^n входів):
 *   K̂(i) = (1/n) * Σ_j [f(x)_j ⊕ f(x ⊕ e_i)_j]  для фіксованого x
 *   K̂    = (1/m) * Σ_i K̂(i)  — середнє по всіх вхідних бітах
 *
 * Тест-вектори: аналоги паттернів зі статті (розширені до 64 байт для WBC1).
 *
 * Збірка:
 *   gcc -O2 -o test_avalanche_paper test_avalanche_paper.c -lssl -lcrypto -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* ── врезаем нужные куски из wbc1_cascade_new.c через define-трюк ─────────── */
#define main wbc_main_unused
#define CASCADE_NO_MAIN 1
/* Отключаем readline в оригинале (не нужен) */
#include "wbc1_cascade_new.c"
#undef main

/* ═══════════════════════════════════════════════════════════════════════════
 * AES-128-ECB single-block encrypt (через OpenSSL EVP)
 * ═══════════════════════════════════════════════════════════════════════════ */
static void aes128_ecb_block(const uint8_t key[16], const uint8_t in[16],
                              uint8_t out[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, 16);
    EVP_CIPHER_CTX_free(ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Обчислити K̂(i) та K̂ для функції шифрування одного блоку (формула (3),
 * sample-оцінка для фіксованого x).
 * fn(key, plain, out) — шифрує block_bytes байт
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef void (*BlockEncFn)(const uint8_t *key, const uint8_t *in, uint8_t *out,
                            int block_bytes);

static double compute_avalanche(BlockEncFn fn, const uint8_t *key,
                                 const uint8_t *plain, int block_bytes,
                                 double *wi_out, int *flip_bit) {
    uint8_t ct0[block_bytes], ct1[block_bytes], mod[block_bytes];
    fn(key, plain, ct0, block_bytes);

    int m = block_bytes * 8;   /* число входных бит */
    int n = block_bytes * 8;   /* число выходных бит */
    double A = 0.0;

    for (int i = 0; i < m; i++) {
        memcpy(mod, plain, block_bytes);
        mod[i / 8] ^= (uint8_t)(1 << (i % 8));
        fn(key, mod, ct1, block_bytes);

        int flips = 0;
        for (int j = 0; j < block_bytes; j++)
            flips += __builtin_popcount(ct0[j] ^ ct1[j]);

        double wi = (double)flips / n;
        if (wi_out && flip_bit && i == *flip_bit)
            *wi_out = wi;
        A += wi;
    }
    return A / m;
}

/* Обёртки с сигнатурой BlockEncFn */
static void wbc1_enc_wrapper(const uint8_t *key, const uint8_t *in,
                              uint8_t *out, int block_bytes) {
    /* build_op_table и build_perm_table нужны перед encrypt_block */
    build_op_table(key);
    g_perm_bs = -1;
    build_perm_table(block_bytes);
    uint8_t rk[KEY_SIZE];
    memcpy(rk, key, KEY_SIZE);
    encrypt_block(rk, in, block_bytes, out);
}

static void aes_enc_wrapper(const uint8_t *key, const uint8_t *in,
                             uint8_t *out, int block_bytes) {
    (void)block_bytes;  /* AES: всегда 16 байт */
    aes128_ecb_block(key, in, out);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════ */
int main(void) {
    /* Паттерны из статьи (16 байт), расширенные до 64 для WBC1 */
    /* Статья: F222...22, 5555...77, AA11...66 */
    static const uint8_t pat16[3][16] = {
        {0xF2,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
         0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22},  /* паттерн 1 */
        {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
         0x55,0x55,0x55,0x55,0x77,0x77,0x77,0x77},  /* паттерн 2 */
        {0xAA,0xAA,0x11,0x11,0x11,0x11,0x11,0x11,
         0x11,0x11,0x11,0x11,0x66,0x66,0x66,0x66},  /* паттерн 3 */
    };
    /* Те же биты из статьи: bit 46, 63, 57 */
    static const int paper_bits[3] = {46, 63, 57};
    /* Бумажные значения W_i для AES из статьи */
    static const double paper_wi[3] = {0.3594, 0.4921, 0.4453};

    /* Фиксированный ключ */
    uint8_t key32[KEY_SIZE];
    memset(key32, 0x01, KEY_SIZE);   /* ключ WBC1: 32 байта */
    uint8_t key16[16];
    memset(key16, 0x01, 16);         /* ключ AES: 16 байт */

    /* Расширяем 16-байтовый паттерн до 64 для WBC1 */
    uint8_t plain64[3][64];
    for (int t = 0; t < 3; t++)
        for (int k = 0; k < 4; k++)
            memcpy(plain64[t] + k * 16, pat16[t], 16);

    printf("═══════════════════════════════════════════════════════════════════\n");
    printf(" Лавинний ефект: порівняння WBC1 (encrypt_block) та AES-128-ECB\n");
    printf(" SAC формули (1)-(3): K_avalanche(i) = 1/(n*2^n) * sum W(a_j^ei)\n");
    printf(" Sample-оцінка K^(i) = (1/n)*sum_j [f(x)_j xor f(x^ei)_j]       \n");
    printf("═══════════════════════════════════════════════════════════════════\n\n");

    printf("%-10s  %-6s  %-12s  %-12s  %-12s  %-12s  %-12s\n",
           "Паттерн", "Біт", "K^i(AES)", "K^i(WBC1)", "K^(AES)", "K^(WBC1)", "K_paper(AES)");
    printf("%s\n", "──────────────────────────────────────────────────────────────────────────────");

    for (int t = 0; t < 3; t++) {
        int flip = paper_bits[t];

        /* AES: блок 16 байт */
        double wi_aes = 0.0;
        int fb_aes = flip;
        double A_aes = compute_avalanche(aes_enc_wrapper, key16,
                                          pat16[t], 16, &wi_aes, &fb_aes);

        /* WBC1: блок 64 байт, бит flip (тот же номер) */
        double wi_wbc = 0.0;
        int fb_wbc = flip;
        double A_wbc = compute_avalanche(wbc1_enc_wrapper, key32,
                                          plain64[t], 64, &wi_wbc, &fb_wbc);

        printf("%-10d  %-6d  %-12.4f  %-12.4f  %-12.4f  %-12.4f  %-12.4f\n",
               t + 1, flip, wi_aes, wi_wbc, A_aes, A_wbc, paper_wi[t]);
    }

    printf("\n%-10s  %-6s  %-12s  %-12s  %-12s  %-12s\n",
           "", "", "K^i(AES)", "K^i(WBC1)", "K^(AES)", "K^(WBC1)");
    printf(" Ідеал (SAC):              0.5000        0.5000        0.5000        0.5000\n");

    /* Средний A по всем 3 паттернам */
    double sum_aes = 0, sum_wbc = 0;
    for (int t = 0; t < 3; t++) {
        int fb = paper_bits[t];
        double wi_a = 0, wi_w = 0;
        sum_aes += compute_avalanche(aes_enc_wrapper, key16, pat16[t], 16, &wi_a, &fb);
        fb = paper_bits[t];
        sum_wbc += compute_avalanche(wbc1_enc_wrapper, key32, plain64[t], 64, &wi_w, &fb);
    }
    printf("\n Середнє K^ по 3 паттернах: AES=%.4f   WBC1=%.4f  (ідеал=0.5000)\n",
           sum_aes / 3, sum_wbc / 3);

    /* Тест на случайных данных (100 запусков, средний A) */
    printf("\n─── Тест на 100 случайных блоках ───────────────────────────────\n");
    double total_aes = 0, total_wbc = 0;
    for (int r = 0; r < 100; r++) {
        uint8_t rnd16[16], rnd64[64];
        RAND_bytes(rnd16, 16);
        for (int k = 0; k < 4; k++) memcpy(rnd64 + k*16, rnd16, 16);
        int fb = -1;
        total_aes += compute_avalanche(aes_enc_wrapper, key16, rnd16, 16, NULL, &fb);
        total_wbc += compute_avalanche(wbc1_enc_wrapper, key32, rnd64, 64, NULL, &fb);
    }
    printf(" AES-128  K^ = %.4f  (ідеал SAC 0.5000)\n", total_aes / 100);
    printf(" WBC1     K^ = %.4f  (ідеал SAC 0.5000)\n", total_wbc / 100);
    printf("════════════════════════════════════════════════════════════════\n");

    return 0;
}
