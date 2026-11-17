/*
 * Lab 2 - Corrected program 2
 * Remediation : Finish all work with the allocation before free(), then set
 *               the pointer to NULL and never dereference it again.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *message = malloc(48);
    if (message == NULL) {
        fprintf(stderr, "[!] Error: malloc() failed for the message buffer.\n");
        return EXIT_FAILURE;
    }

    strcpy(message, "Heap memory before free");
    printf("[*] Before free(): %s\n", message);

    /* All required operations are completed while the allocation is live. */
    size_t length = strlen(message);
    printf("[*] Length calculated before free(): %zu\n", length);

    free(message);
    message = NULL;

    printf("[+] Pointer set to NULL after free().\n");

    /* Safe post-free check: no dereference of released memory. */
    if (message == NULL) {
        printf("[*] Post-free guard confirms the pointer is NULL.\n");
    }

    return EXIT_SUCCESS;
}
