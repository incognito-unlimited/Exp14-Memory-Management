/*
 * Lab 2 - Corrected program 1
 * Remediation : Validate every malloc() result before use.
 *
 * By default a small, realistic allocation is used. The optional argument
 * --simulate-oom requests SIZE_MAX bytes so the allocation-failure path can
 * be tested deterministically without relying on the machine running out of
 * memory naturally.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_BYTES 64u

int main(int argc, char **argv)
{
    size_t requested_bytes = DEFAULT_BYTES;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [--simulate-oom]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        if (strcmp(argv[1], "--simulate-oom") == 0) {
            requested_bytes = SIZE_MAX;
        } else {
            fprintf(stderr, "[!] Unknown option: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    }

    printf("[*] Requesting %zu bytes of heap memory...\n", requested_bytes);

    char *buffer = malloc(requested_bytes);
    if (buffer == NULL) {
        fprintf(stderr,
                "[!] Error: malloc() failed for %zu bytes; no memory was written.\n",
                requested_bytes);
        return EXIT_FAILURE;
    }

    snprintf(buffer, requested_bytes, "%s", "Checked allocation demonstration");
    printf("[*] Buffer contents: %s\n", buffer);

    free(buffer);
    buffer = NULL;

    printf("[+] Memory freed and pointer set to NULL.\n");
    return EXIT_SUCCESS;
}
