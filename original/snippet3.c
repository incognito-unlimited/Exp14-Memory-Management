/*
 * Lab 2 - Original vulnerable program 3
 * Vulnerability : Double-free
 * Weakness       : CWE-415 Double Free
 *
 * The same allocation is released twice. The pointer is not reset after the
 * first free(), so the second free() passes a stale pointer to the allocator.
 */
#include <stdio.h>
#include <stdlib.h>

/*
 * Kept in a separate, non-inlined function so that the deliberately
 * undefined second release is not optimized away at -O1. The vulnerability
 * itself is the second free(); this attribute only makes it observable.
 */
__attribute__((noinline)) static void release_again(int *pointer)
{
    free(pointer);
}

int main(void)
{
    int *scores = malloc(4 * sizeof(*scores));
    if (scores == NULL) {
        return EXIT_FAILURE;
    }

    scores[0] = 10;
    scores[1] = 20;
    scores[2] = 30;
    scores[3] = 40;

    printf("[*] Sum: %d\n", scores[0] + scores[1] + scores[2] + scores[3]);

    free(scores);
    printf("[+] First free() completed.\n");

    /* VULNERABILITY: second free() of the same address. */
    release_again(scores);
    printf("[!] Second free() attempted.\n");

    return 0;
}
