/*
 * Lab 2 - Original vulnerable program 1
 * Vulnerability : Unchecked malloc() return value
 * Weakness       : CWE-476 NULL Pointer Dereference / CWE-754 Improper Check
 *
 * This program deliberately requests an impossibly large heap block so that
 * malloc() fails and returns NULL. The return value is never checked before
 * the memory is written, which produces a NULL-pointer dereference.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const size_t requested_bytes = SIZE_MAX;

    printf("[*] Requesting %zu bytes of heap memory...\n", requested_bytes);

    /* VULNERABILITY: malloc() may fail and return NULL; no check is performed. */
    char *buffer = malloc(requested_bytes);

    /* VULNERABILITY: returned pointer is dereferenced without validation. */
    strcpy(buffer, "Unchecked allocation demonstration");

    printf("[*] Buffer contents: %s\n", buffer);

    free(buffer);
    buffer = NULL;

    return 0;
}
