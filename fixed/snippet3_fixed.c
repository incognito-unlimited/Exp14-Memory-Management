/*
 * Lab 2 - Corrected program 3
 * Remediation : Free exactly once, set the pointer to NULL immediately, and
 *               make repeated release attempts harmless through a guard.
 */
#include <stdio.h>
#include <stdlib.h>

static void release_once(int **pointer)
{
    if (pointer != NULL && *pointer != NULL) {
        free(*pointer);
        *pointer = NULL;
        printf("[+] Allocation freed once; pointer set to NULL.\n");
    } else {
        printf("[*] Pointer is already NULL; duplicate free skipped.\n");
    }
}

int main(void)
{
    int *scores = malloc(4 * sizeof(*scores));
    if (scores == NULL) {
        fprintf(stderr, "[!] Error: malloc() failed for the scores array.\n");
        return EXIT_FAILURE;
    }

    scores[0] = 10;
    scores[1] = 20;
    scores[2] = 30;
    scores[3] = 40;

    printf("[*] Sum: %d\n", scores[0] + scores[1] + scores[2] + scores[3]);

    release_once(&scores);

    /* A second call is now intentionally harmless. */
    release_once(&scores);

    return EXIT_SUCCESS;
}
