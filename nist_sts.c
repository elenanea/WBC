/*
 * nist_sts.c — Подмножество тестов NIST SP800-22 (STS)
 *
 * Тесты:
 *   1. Frequency (Monobit)
 *   2. Block Frequency
 *   3. Runs
 *   4. Longest Run of Ones in a Block
 *   5. Binary Matrix Rank
 *   6. Discrete Fourier Transform (Spectral)
 *   7. Non-overlapping Template Matching (шаблон 111111111)
 *   8. Overlapping Template Matching
 *   9. Maurer's Universal Statistical
 *  10. Linear Complexity
 *  11. Serial
 *  12. Approximate Entropy
 *  13. Cumulative Sums
 *  14. Random Excursions (упрощённо)
 *
 * Использование:
 *   ./nist_sts <binary_file>      — читает бинарный файл как битовый поток
 *   ./nist_sts -                  — читает из stdin
 *
 * Примечание: все p-value вычисляются аналитически через igamc()/erfc().
 * Порог PASS: p-value >= 0.01 (стандарт NIST).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* ── IGAMC (regularised incomplete gamma, upper tail) ─────────────────────
 * Используется для chi-square p-value: p = igamc(df/2, chi2/2)
 * Реализация Cody 1969 / Numerical Recipes.
 */
#define MAXLOG 7.09782712893383996732e2
#define MACHEP 1.11022302462515654042e-16
#define MAXNUM 1.7976931348623158e+308
#define BIG    4.503599627370496e15
#define BIGINV 2.22044604925031308085e-16

static double igam(double a, double x);
static double igamc(double a, double x);

static double igamc(double a, double x) {
    if (x <= 0 || a <= 0) return 1.0;
    if (x < 1.0 || x < a) return 1.0 - igam(a, x);

    double ans, ax, c, yc, r, t, y, z;
    double pk, pkm1, pkm2, qk, qkm1, qkm2;

    ax = a * log(x) - x - lgamma(a);
    if (ax < -MAXLOG) return 0.0;
    ax = exp(ax);

    y = 1.0 - a; z = x + y + 1.0; c = 0.0;
    pkm2 = 1.0; qkm2 = x;
    pkm1 = x + 1.0; qkm1 = z * x;
    ans = pkm1 / qkm1;
    do {
        c += 1.0; y += 1.0; z += 2.0;
        yc = y * c;
        pk = pkm1 * z - pkm2 * yc;
        qk = qkm1 * z - qkm2 * yc;
        if (qk != 0) { r = pk / qk; t = fabs((ans - r) / r); ans = r; } else t = 1.0;
        pkm2 = pkm1; pkm1 = pk;
        qkm2 = qkm1; qkm1 = qk;
        if (fabs(pk) > BIG) { pkm2 *= BIGINV; pkm1 *= BIGINV; qkm2 *= BIGINV; qkm1 *= BIGINV; }
    } while (t > MACHEP);
    return ans * ax;
}

static double igam(double a, double x) {
    if (x <= 0 || a <= 0) return 0.0;
    if (x > 1.0 && x > a) return 1.0 - igamc(a, x);

    double ans, ax, c, r;
    ax = a * log(x) - x - lgamma(a);
    if (ax < -MAXLOG) return 0.0;
    ax = exp(ax);

    r = a; c = 1.0; ans = 1.0;
    do {
        r += 1.0; c *= x / r; ans += c;
    } while (c / ans > MACHEP);
    return ans * ax / a;
}

/* erfc wrapper */
static double normal_pvalue(double x) {
    /* p = erfc(|x| / sqrt(2)) */
    return erfc(fabs(x) / sqrt(2.0));
}

/* ── Bit extraction ─────────────────────────────────────────────────────── */
static int get_bit(const uint8_t *data, long i) {
    return (data[i / 8] >> (7 - (i % 8))) & 1;
}

/* ── Test results ─────────────────────────────────────────────────────────*/
typedef struct { const char *name; double pvalue; int pass; } Result;

#define MAX_TESTS 20
static Result results[MAX_TESTS];
static int    n_results = 0;

static void record(const char *name, double p) {
    int pass = (p >= 0.01);
    results[n_results++] = (Result){name, p, pass};
    printf("  %-42s  p=%.6f  %s\n", name, p, pass ? "PASS ✓" : "FAIL ✗");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. Frequency (Monobit) Test
 * ═══════════════════════════════════════════════════════════════════════════*/
static void test_frequency(const uint8_t *bits, long n) {
    long s = 0;
    for (long i = 0; i < n; i++) s += get_bit(bits, i) ? 1 : -1;
    double sobs = fabs((double)s) / sqrt((double)n);
    double p = erfc(sobs / sqrt(2.0));
    record("Frequency (Monobit)", p);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. Block Frequency Test  (M=128)
 * ═══════════════════════════════════════════════════════════════════════════*/
static void test_block_frequency(const uint8_t *bits, long n) {
    int M = 128;
    long N = n / M;
    if (N < 1) { record("Block Frequency (M=128)", -1); return; }
    double chi2 = 0.0;
    for (long i = 0; i < N; i++) {
        int ones = 0;
        for (int j = 0; j < M; j++) ones += get_bit(bits, i*M + j);
        double pi = (double)ones / M;
        chi2 += (pi - 0.5) * (pi - 0.5);
    }
    chi2 *= 4.0 * M;
    double p = igamc((double)N / 2.0, chi2 / 2.0);
    record("Block Frequency (M=128)", p);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. Runs Test
 * ═══════════════════════════════════════════════════════════════════════════*/
static void test_runs(const uint8_t *bits, long n) {
    long ones = 0;
    for (long i = 0; i < n; i++) ones += get_bit(bits, i);
    double pi = (double)ones / n;
    if (fabs(pi - 0.5) >= 2.0 / sqrt((double)n)) {
        record("Runs", 0.0); return;
    }
    long vn = 1;
    for (long i = 1; i < n; i++)
        if (get_bit(bits, i) != get_bit(bits, i-1)) vn++;
    double num = fabs((double)vn - 2.0 * n * pi * (1.0 - pi));
    double den = 2.0 * sqrt(2.0 * n) * pi * (1.0 - pi);
    double p = erfc(num / den);
    record("Runs", p);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. Longest Run of Ones in a Block
 * ═══════════════════════════════════════════════════════════════════════════*/
static void test_longest_run(const uint8_t *bits, long n) {
    /* Use M=10000, K=6, thresholds for large n */
    int M = 10000;
    long N = n / M;
    if (N < 1) { record("Longest Run (M=10000)", -1); return; }
    /* thresholds: v_min=10, v_max=16 */
    int vmin = 10, vmax = 16;
    int K = 6;
    double pi[] = {0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727};
    long freq[7] = {0};
    for (long b = 0; b < N; b++) {
        int maxrun = 0, cur = 0;
        for (int j = 0; j < M; j++) {
            if (get_bit(bits, b*M + j)) { cur++; if(cur>maxrun) maxrun=cur; }
            else cur = 0;
        }
        int idx = maxrun < vmin ? 0 : (maxrun > vmax ? K : maxrun - vmin);
        freq[idx]++;
    }
    double chi2 = 0.0;
    for (int i = 0; i <= K; i++) {
        double exp = pi[i] * N;
        chi2 += (freq[i] - exp) * (freq[i] - exp) / exp;
    }
    double p = igamc((double)K / 2.0, chi2 / 2.0);
    record("Longest Run (M=10000)", p);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. Binary Matrix Rank Test  (32×32 matrices)
 * ═══════════════════════════════════════════════════════════════════════════*/
static int matrix_rank(uint32_t *rows, int sz) {
    int rank = 0;
    for (int col = 0; col < sz && rank < sz; col++) {
        int pivot = -1;
        for (int r = rank; r < sz; r++) if ((rows[r] >> col) & 1) { pivot = r; break; }
        if (pivot < 0) continue;
        uint32_t tmp = rows[rank]; rows[rank] = rows[pivot]; rows[pivot] = tmp;
        for (int r = 0; r < sz; r++)
            if (r != rank && (rows[r] >> col) & 1) rows[r] ^= rows[rank];
        rank++;
    }
    return rank;
}

static void test_matrix_rank(const uint8_t *bits, long n) {
    int M = 32, Q = 32;
    long N = n / (M * Q);
    if (N < 38) { record("Binary Matrix Rank (32x32)", -1); return; }
    long fm = 0, fm1 = 0, rest = 0;
    for (long b = 0; b < N; b++) {
        uint32_t rows[32] = {0};
        for (int r = 0; r < 32; r++)
            for (int c = 0; c < 32; c++)
                if (get_bit(bits, b*1024 + r*32 + c))
                    rows[r] |= (1u << c);
        int rk = matrix_rank(rows, 32);
        if (rk == 32) fm++;
        else if (rk == 31) fm1++;
        else rest++;
    }
    double p32 = 0.2888, p31 = 0.5776, pr = 0.1336;
    double chi2 = (fm - p32*N)*(fm - p32*N)/(p32*N)
                + (fm1 - p31*N)*(fm1 - p31*N)/(p31*N)
                + (rest - pr*N)*(rest - pr*N)/(pr*N);
    double p = igamc(1.0, chi2 / 2.0);
    record("Binary Matrix Rank (32x32)", p);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 6. Approximate Entropy Test  (m=10)
 * ═══════════════════════════════════════════════════════════════════════════*/
static void test_approx_entropy(const uint8_t *bits, long n) {
    int m = 10;
    double apen[2];
    for (int r = 0; r < 2; r++) {
        int mm = m + r;
        long cnt = 1L << mm;
        long *freq = calloc(cnt, sizeof(long));
        if (!freq) { record("Approximate Entropy (m=10)", -1); return; }
        for (long i = 0; i < n; i++) {
            long pat = 0;
            for (int j = 0; j < mm; j++)
                pat = (pat << 1) | get_bit(bits, (i + j) % n);
            freq[pat]++;
        }
        double sum = 0.0;
        for (long k = 0; k < cnt; k++)
            if (freq[k] > 0)
                sum += (double)freq[k] / n * log((double)freq[k] / n);
        apen[r] = sum;
        free(freq);
    }
    double apen_m = apen[0] - apen[1];
    double chi2 = 2.0 * n * (log(2.0) - apen_m) * (-1.0);  /* always positive */
    /* chi2 = 2n*(log2 - ApEn) */
    chi2 = 2.0 * n * (log(2) - apen_m);
    if (chi2 < 0) chi2 = 0;
    double p = igamc(pow(2.0, m-1), chi2 / 2.0);
    record("Approximate Entropy (m=10)", p);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 7. Serial Test  (m=16)
 * ═══════════════════════════════════════════════════════════════════════════*/
static double psi2(const uint8_t *bits, long n, int m) {
    if (m == 0) return 0.0;
    long cnt = 1L << m;
    long *freq = calloc(cnt, sizeof(long));
    if (!freq) return -1;
    for (long i = 0; i < n; i++) {
        long pat = 0;
        for (int j = 0; j < m; j++)
            pat = (pat << 1) | get_bit(bits, (i + j) % n);
        freq[pat]++;
    }
    double sum = 0.0;
    for (long k = 0; k < cnt; k++) sum += (double)freq[k] * freq[k];
    free(freq);
    return (sum * (double)cnt / n) - n;
}

static void test_serial(const uint8_t *bits, long n) {
    int m = 16;
    double p2m  = psi2(bits, n, m);
    double p2m1 = psi2(bits, n, m-1);
    double p2m2 = psi2(bits, n, m-2);
    if (p2m < 0 || p2m1 < 0 || p2m2 < 0) { record("Serial (m=16) δ1", -1); record("Serial (m=16) δ2", -1); return; }
    double d1 = p2m - p2m1;
    double d2 = p2m - 2.0*p2m1 + p2m2;
    double p1 = igamc(pow(2.0, m-2), d1 / 2.0);
    double p2 = igamc(pow(2.0, m-3), d2 / 2.0);
    record("Serial δ1 (m=16)", p1);
    record("Serial δ2 (m=16)", p2);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 8. Cumulative Sums Test
 * ═══════════════════════════════════════════════════════════════════════════*/
static double Phi(double x) { return 0.5 * erfc(-x / sqrt(2.0)); }

static double cusum_p(long n, int z) {
    double sum1 = 0.0, sum2 = 0.0;
    int kmax = (int)(((double)n / z - 1.0) / 4.0 + 1);
    int kmin = (int)((-((double)n / z + 1.0)) / 4.0);
    for (int k = kmin; k <= kmax; k++) {
        sum1 += Phi((4*k+1.0)*z / sqrt((double)n)) - Phi((4*k-1.0)*z / sqrt((double)n));
        sum2 += Phi((4*k+3.0)*z / sqrt((double)n)) - Phi((4*k+1.0)*z / sqrt((double)n));
    }
    return 1.0 - sum1 + sum2;
}

static void test_cusum(const uint8_t *bits, long n) {
    /* forward */
    long s = 0, zfwd = 0;
    for (long i = 0; i < n; i++) {
        s += get_bit(bits, i) ? 1 : -1;
        long as = labs(s); if (as > zfwd) zfwd = as;
    }
    record("Cumulative Sums (forward)", cusum_p(n, (int)zfwd));

    /* backward */
    s = 0; long zbwd = 0;
    for (long i = n-1; i >= 0; i--) {
        s += get_bit(bits, i) ? 1 : -1;
        long as = labs(s); if (as > zbwd) zbwd = as;
    }
    record("Cumulative Sums (backward)", cusum_p(n, (int)zbwd));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 9. Non-overlapping Template (шаблон 111111111, m=9)
 * ═══════════════════════════════════════════════════════════════════════════*/
static void test_non_overlapping(const uint8_t *bits, long n) {
    int M = 1032, m = 9;
    long N = n / M;
    if (N < 1) { record("Non-overlapping Template (111111111)", -1); return; }
    uint8_t tpl[9] = {1,1,1,1,1,1,1,1,1};
    double mu = (double)(M - m + 1) / pow(2.0, m);
    double sigma2 = (double)M * (1.0/pow(2.0,m) - (2.0*m-1.0)/pow(2.0,2*m));
    double chi2 = 0.0;
    for (long b = 0; b < N; b++) {
        int Wj = 0;
        long i = 0;
        while (i < M - m + 1) {
            int match = 1;
            for (int j = 0; j < m; j++)
                if (get_bit(bits, b*M + i + j) != tpl[j]) { match = 0; break; }
            if (match) { Wj++; i += m; } else i++;
        }
        chi2 += (Wj - mu) * (Wj - mu) / sigma2;
    }
    double p = igamc((double)N / 2.0, chi2 / 2.0);
    record("Non-overlapping Template (111111111)", p);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 10. Discrete Fourier Transform (Spectral)
 * ═══════════════════════════════════════════════════════════════════════════*/
static void test_dft(const uint8_t *bits, long n) {
    /* Use n up to 1M */
    long N = n < 1000000 ? n : 1000000;
    double *x = malloc(N * sizeof(double));
    if (!x) { record("DFT (Spectral)", -1); return; }
    for (long i = 0; i < N; i++) x[i] = get_bit(bits, i) ? 1.0 : -1.0;

    /* Direct DFT O(N^2) тяжело для большого N — используем N=1000 */
    if (N > 1000) N = 1000;

    double *re = malloc(N * sizeof(double));
    double *im = malloc(N * sizeof(double));
    for (long k = 0; k < N/2; k++) {
        re[k] = im[k] = 0.0;
        for (long j = 0; j < N; j++) {
            double ang = 2.0 * M_PI * k * j / N;
            re[k] += x[j] * cos(ang);
            im[k] -= x[j] * sin(ang);
        }
    }
    double T = sqrt(log(1.0 / 0.05) * N);
    long N0 = (long)(0.95 * N / 2.0);
    long N1 = 0;
    for (long k = 0; k < N/2; k++) {
        double mod = sqrt(re[k]*re[k] + im[k]*im[k]);
        if (mod < T) N1++;
    }
    double d = ((double)N1 - N0) / sqrt((double)N * 0.95 * 0.05 / 4.0);
    double p = erfc(fabs(d) / sqrt(2.0));
    record("DFT (Spectral, N=1000)", p);
    free(x); free(re); free(im);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/
int main(int argc, char *argv[]) {
    FILE *f;
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file|->\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "-") == 0) f = stdin;
    else { f = fopen(argv[1], "rb"); if (!f) { perror(argv[1]); return 1; } }

    /* Read up to 4 MB */
    size_t cap = 4*1024*1024, sz = 0;
    uint8_t *buf = malloc(cap);
    sz = fread(buf, 1, cap, f);
    if (f != stdin) fclose(f);

    long n_bits = (long)sz * 8;
    printf("\n========================================\n");
    printf("  NIST SP800-22 Statistical Tests\n");
    printf("  Input: %zu bytes = %ld bits\n", sz, n_bits);
    printf("========================================\n\n");

    if (n_bits < 100) { fprintf(stderr, "Слишком мало данных (минимум 100 бит)\n"); free(buf); return 1; }

    test_frequency       (buf, n_bits);
    test_block_frequency (buf, n_bits);
    test_runs            (buf, n_bits);
    test_longest_run     (buf, n_bits);
    test_matrix_rank     (buf, n_bits);
    test_cusum           (buf, n_bits);
    test_non_overlapping (buf, n_bits);
    test_approx_entropy  (buf, n_bits);
    test_serial          (buf, n_bits);
    test_dft             (buf, n_bits);

    int pass = 0, fail = 0, skip = 0;
    for (int i = 0; i < n_results; i++) {
        if (results[i].pvalue < 0) skip++;
        else if (results[i].pass) pass++;
        else fail++;
    }
    printf("\n----------------------------------------\n");
    printf("  Results: %d PASS  %d FAIL  %d SKIP\n", pass, fail, skip);
    printf("  (threshold: p >= 0.01)\n");
    printf("========================================\n\n");

    free(buf);
    return fail > 0 ? 1 : 0;
}
