/* test_dck_rounds.c — измеряет avalanche derive_cascade_key при разных раундах */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define KEY_SIZE 32

static uint8_t rotate_left(uint8_t v, int n)  { n &= 7; return (v << n) | (v >> (8-n)); }
static uint8_t rotate_right(uint8_t v, int n) { n &= 7; return (v >> n) | (v << (8-n)); }

static void dck(const uint8_t *enc_block, int block_bytes, uint8_t new_rk[KEY_SIZE], int ROUNDS) {
    uint8_t S[64] = {0};
    for (int j = 0; j < block_bytes; j++) S[j & 63] ^= enc_block[j];

    for (int r = 0; r < ROUNDS; r++) {
        uint8_t c = (uint8_t)(S[63] ^ r);
        for (int i = 0; i < 64; i++) {
            c = (uint8_t)(S[i] + rotate_left(c, 5) + (uint8_t)(67*i + 29*r));
            S[i] = c;
        }
        c = (uint8_t)(S[0] ^ (uint8_t)(r * 37));
        for (int i = 63; i >= 0; i--) {
            c = S[i] ^ rotate_right(c, 3);
            S[i] = c;
        }
    }
    memcpy(new_rk, S, KEY_SIZE);
}

static int popcount8(uint8_t v) {
    int c = 0;
    while (v) { c += v & 1; v >>= 1; }
    return c;
}

/* Avalanche: меняем по одному биту входа, считаем % изменённых бит в выходе */
static double avalanche(int rounds, int trials) {
    uint8_t block[64], out1[KEY_SIZE], out2[KEY_SIZE];
    long total_diff = 0, total_bits = 0;
    /* simple LCG seed */
    uint32_t rng = 0xDEADBEEF;
    for (int t = 0; t < trials; t++) {
        /* случайный блок */
        for (int i = 0; i < 64; i++) { rng = rng*1664525 + 1013904223; block[i] = rng & 0xFF; }
        dck(block, 64, out1, rounds);
        /* флипаем каждый бит по очереди */
        for (int byte = 0; byte < 64; byte++) {
            for (int bit = 0; bit < 8; bit++) {
                block[byte] ^= (1 << bit);
                dck(block, 64, out2, rounds);
                block[byte] ^= (1 << bit);
                for (int k = 0; k < KEY_SIZE; k++) total_diff += popcount8(out1[k] ^ out2[k]);
                total_bits += KEY_SIZE * 8;
            }
        }
    }
    return 100.0 * total_diff / total_bits;
}

int main(void) {
    int test_rounds[] = {1, 2, 3, 4, 5, 6, 8, 10, 12, 16};
    int n = sizeof(test_rounds)/sizeof(test_rounds[0]);
    int trials = 30;

    printf("Rounds | Avalanche%%  | Оценка\n");
    printf("-------|------------|--------\n");
    for (int i = 0; i < n; i++) {
        double av = avalanche(test_rounds[i], trials);
        const char *verdict;
        if      (av >= 49.0 && av <= 51.0) verdict = "IDEAL";
        else if (av >= 47.0)               verdict = "OK";
        else if (av >= 44.0)               verdict = "WEAK";
        else                               verdict = "BAD";
        printf("  %2d   |  %6.2f%%   | %s\n", test_rounds[i], av, verdict);
    }
    return 0;
}
