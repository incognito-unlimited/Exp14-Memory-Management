/*
 * Lab 2 - Original vulnerable program 2
 * Vulnerability : Heap use-after-free
 * Weakness       : CWE-416 Use After Free
 *
 * The pointer is dereferenced both for reading and for writing after the
 * allocation it references has already been released with free().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *message = malloc(48);
    if (message == NULL) {
        return EXIT_FAILURE;
    }

    strcpy(message, "Heap memory before free");
    printf("[*] Before free(): %s\n", message);

    free(message);

    /* VULNERABILITY: read from freed heap memory. */
    printf("[!] After free(): %s\n", message);

    /* VULNERABILITY: write to freed heap memory. */
    message[0] = 'X';
    printf("[!] After writing to freed memory: %s\n", message);

    return 0;
}
