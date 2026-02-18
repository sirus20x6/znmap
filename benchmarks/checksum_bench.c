/*
 * Checksum microbenchmark — measures ip_cksum_add throughput.
 * Calls ip_cksum_add() in a tight loop on random data (1M iterations).
 * Link against either the original libdnet or the Zig replacement.
 *
 * Build: cc -O2 -o checksum_bench checksum_bench.c -I../libdnet-stripped/include \
 *        ../libdnet-stripped/src/.libs/libdnet.a  (or zig/checksum.o)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* ip_cksum_add prototype — matches both libdnet and Zig export */
extern int ip_cksum_add(const void *buf, size_t len, int cksum);

#define ITERATIONS 1000000
#define BUF_SIZE   1500  /* typical MTU */

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(rand() & 0xFF);
}

int main(void) {
    uint8_t buf[BUF_SIZE];
    srand(42);  /* deterministic */
    fill_random(buf, BUF_SIZE);

    printf("Checksum microbenchmark: %d iterations, %d byte packets\n",
           ITERATIONS, BUF_SIZE);

    struct timespec start, end;
    volatile int sum = 0;  /* prevent optimization */

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        sum = ip_cksum_add(buf, BUF_SIZE, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = ITERATIONS / elapsed;
    double gbps = (ops_per_sec * BUF_SIZE * 8) / 1e9;

    printf("Time: %.4f seconds\n", elapsed);
    printf("Throughput: %.2f M checksums/sec\n", ops_per_sec / 1e6);
    printf("Bandwidth: %.2f Gbps\n", gbps);
    printf("Final checksum: 0x%08x (to prevent dead code elimination)\n", sum);

    return 0;
}
