# Laboratory Report — Lab 2

## Memory Management Error Identification and Remediation

| Field | Detail |
|---|---|
| Subject | Secure Coding and Vulnerabilities |
| Experiment | Lab 2 |
| Student | Aditey Mehra |
| University | K.R. Mangalam University |
| Roll Number | 2301730266 |
| Programme | B.Tech Computer Science and Engineering |
| Specialisation | Artificial Intelligence and Machine Learning |
| Section | D |
| Semester | 7 |
| GitHub repository | https://github.com/incognito-unlimited/Exp14-Memory-Management |

---

## 1. Aim

To identify, analyse, reproduce and remediate three memory-management errors in C — an unchecked `malloc()` return value, a heap use-after-free and a double-free — and to verify the corrected programs using compiler warnings, AddressSanitizer and GDB.

## 2. Objectives

1. Understand the behaviour of `malloc()` when allocation fails.
2. Recognise invalid pointer use after `free()`.
3. Understand why an allocation must be released exactly once.
4. Write original vulnerable programs that isolate each defect.
5. Write corrected programs that validate allocations, avoid post-free access, reset pointers to `NULL` and prevent duplicate deallocation.
6. Compile every program with strict warnings and AddressSanitizer.
7. Capture genuine compiler, sanitizer and debugger evidence.
8. Classify each vulnerability by CWE and explain its security impact.
9. Publish the repository on GitHub with source code, evidence and reports.

## 3. Introduction

C gives the programmer direct control over heap memory through `malloc()` and `free()`. That control is powerful but unforgiving: the allocator does not protect the program from invalid pointer use. Three particularly common defects are:

- **Unchecked allocation result.** `malloc()` returns `NULL` on failure. Writing through that value causes a null-pointer dereference. A small allocation often succeeds, so the defect can remain hidden until the system is under memory pressure or the request is unusually large.
- **Use-after-free.** After `free(p)`, the pointer `p` still holds a numeric address, but the memory belongs to the allocator. Reading or writing through `p` is undefined behaviour.
- **Double-free.** Passing the same address to `free()` twice corrupts allocator bookkeeping and can be escalated to arbitrary memory writes in exploitable conditions.

AddressSanitizer (ASan) instruments allocations and pointer accesses. It poisons freed regions, maintains redzones and reports the exact source line at which an invalid access occurs. This makes it an appropriate verification tool for this experiment.

No faculty-provided source files or separate reference-report snippets were present in the workspace. The vulnerable programs below were therefore written specifically for this lab from the experiment requirements; the corrected implementations preserve the same scenarios.

## 4. Classified Error Table

| ID | Error | CWE | Mistake | Impact | Remediation |
|----|-------|-----|---------|--------|-------------|
| E1 | Unchecked `malloc()` return value | CWE-476, CWE-754 | `malloc(SIZE_MAX)` result is used without a NULL check | Crash / denial of service; unsafe failure handling | Check result, report error, exit safely, free and NULL the pointer |
| E2 | Heap use-after-free | CWE-416 | Buffer is read and written after `free()` | Information disclosure, heap corruption, possible code execution | Finish all work before free; set pointer to NULL; never dereference afterwards |
| E3 | Double-free | CWE-415 | Same allocation is freed twice | Allocator metadata corruption, crash, possible arbitrary write | Free exactly once in a guarded helper; NULL the pointer immediately |

Full classification details are in `report/error_classification.md`.

## 5. Original and Corrected Code

### 5.1 Program 1 — Unchecked `malloc()`

**Original — `original/snippet1.c`**

```c
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
```

**Mistake:** the return value of `malloc()` is never compared with `NULL`. The deliberately impossible request makes the failure deterministic.

**Corrected — `fixed/snippet1_fixed.c`**

```c
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
```

### 5.2 Program 2 — Heap use-after-free

**Original — `original/snippet2.c`**

```c
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
```

**Mistake:** the pointer is dereferenced for reading and writing after the allocation has been released.

**Corrected — `fixed/snippet2_fixed.c`**

```c
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
```

### 5.3 Program 3 — Double-free

**Original — `original/snippet3.c`**

```c
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
```

**Mistake:** `scores` is not set to `NULL` after the first `free()`, so the same address is released again. The `noinline` helper does not cause the bug; it only prevents the optimiser from hiding the deliberate second release.

**Corrected — `fixed/snippet3_fixed.c`**

```c
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
```

## 6. Compilation and Testing

### Environment

```text
Host            : Linux 6.18.54.1-microsoft-standard-WSL2 x86_64
Distribution    : Ubuntu 26.04.1 LTS
Compiler        : gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0
GDB             : GNU gdb (Ubuntu 17.1-2ubuntu1) 17.1
Flags           : -Wall -Wextra -std=c11 -g -O1 -fsanitize=address -fno-omit-frame-pointer
ASAN_OPTIONS    : detect_leaks=1:halt_on_error=1:allocator_may_return_null=1:print_stacktrace=1
```

### Commands executed

```bash
mkdir -p build
FLAGS="-Wall -Wextra -std=c11 -g -O1 -fsanitize=address -fno-omit-frame-pointer"

gcc $FLAGS original/snippet1.c -o build/snippet1
gcc $FLAGS original/snippet2.c -o build/snippet2
gcc $FLAGS original/snippet3.c -o build/snippet3

gcc $FLAGS fixed/snippet1_fixed.c -o build/snippet1_fixed
gcc $FLAGS fixed/snippet2_fixed.c -o build/snippet2_fixed
gcc $FLAGS fixed/snippet3_fixed.c -o build/snippet3_fixed
```

All six compilations returned `exit_code=0`. The original programs intentionally produced warnings such as `-Walloc-size-larger-than` and `-Wuse-after-free`; the corrected programs produced no compiler diagnostics. The complete transcript is in `evidence/compilation_results.txt`.

## 7. AddressSanitizer Clean-Run Evidence

Commands executed for the corrected programs:

```bash
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:allocator_may_return_null=1:print_stacktrace=1

./build/snippet1_fixed
./build/snippet2_fixed
./build/snippet3_fixed
./build/snippet1_fixed --simulate-oom
```

Actual output:

```text
----- ./build/snippet1_fixed -----
[*] Requesting 64 bytes of heap memory...
[*] Buffer contents: Checked allocation demonstration
[+] Memory freed and pointer set to NULL.
exit_code=0

----- ./build/snippet2_fixed -----
[*] Before free(): Heap memory before free
[*] Length calculated before free(): 23
[+] Pointer set to NULL after free().
[*] Post-free guard confirms the pointer is NULL.
exit_code=0

----- ./build/snippet3_fixed -----
[*] Sum: 100
[+] Allocation freed once; pointer set to NULL.
[*] Pointer is already NULL; duplicate free skipped.
exit_code=0

----- allocation-failure path check -----
==482==WARNING: AddressSanitizer failed to allocate 0xffffffffffffffff bytes
[!] Error: malloc() failed for 18446744073709551615 bytes; no memory was written.
[*] Requesting 18446744073709551615 bytes of heap memory...
exit_code=1
```

No AddressSanitizer `ERROR:` line appeared for the normal corrected runs. The `--simulate-oom` run contains an advisory allocation warning but no invalid memory access; the application detects the failure, prints its error and exits safely with code `1`. Complete output: `evidence/asan_results.txt`.

Screenshot: `evidence/screenshots/04_asan_clean_run.png`.

## 8. Original Program Error Detection

The original programs were executed with the same `ASAN_OPTIONS` and produced genuine diagnostics:

```text
snippet1: ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
          The signal is caused by a WRITE memory access.
          Hint: address points to the zero page.
          #2 ... in main original/snippet1.c:25
          exit_code=1

snippet2: ERROR: AddressSanitizer: heap-use-after-free on address ...
          WRITE of size 1 ...
          #0 ... in main original/snippet2.c:29
          SUMMARY: AddressSanitizer: heap-use-after-free original/snippet2.c:29 in main
          exit_code=1

snippet3: ERROR: AddressSanitizer: attempting double-free on ...
          #1 ... in release_again original/snippet3.c:19
          SUMMARY: AddressSanitizer: double-free original/snippet3.c:19 in release_again
          exit_code=1
```

These results are stored separately in `evidence/original_asan_results.txt` so they cannot be confused with the corrected-program results. Screenshot: `evidence/screenshots/05_original_asan_errors.png`.

## 9. GDB Debugging Verification

GDB was available, so `build/snippet1_fixed` was debugged. `ASAN_OPTIONS=detect_leaks=0` was used because LeakSanitizer cannot run reliably under `ptrace`.

```bash
ASAN_OPTIONS=detect_leaks=0 gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'set confirm off' \
  -ex 'break main' \
  -ex 'run' \
  -ex 'bt' \
  -ex 'continue' \
  ./build/snippet1_fixed
```

Actual output:

```text
Breakpoint 1 at 0x1289: file fixed/snippet1_fixed.c, line 18.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=1, argv=0x7fffffffe558) at fixed/snippet1_fixed.c:18
18      {
#0  main (argc=1, argv=0x7fffffffe558) at fixed/snippet1_fixed.c:18
[*] Requesting 64 bytes of heap memory...
[*] Buffer contents: Checked allocation demonstration
[+] Memory freed and pointer set to NULL.
[Inferior 1 (process 512) exited normally]
```

This confirms the breakpoint at `main()`, execution of the corrected program and normal termination. Full output: `evidence/gdb_results.txt`. Screenshot: `evidence/screenshots/06_gdb_verification.png`.

## 10. GitHub Repository

The repository was published as a public repository:

**URL:** https://github.com/incognito-unlimited/Exp14-Memory-Management

Publication workflow:

```bash
gh auth status
git init
git checkout -b main
git add .
git commit -m "Complete Lab 2 memory management analysis, remediation and evidence"
gh repo create incognito-unlimited/Exp14-Memory-Management --public --source=. --remote=origin --push
git status
```

Screenshot after pushing: `evidence/screenshots/07_github_repository.png`.

## 11. Result

| Check | Outcome |
|---|---|
| Six C source files present | Yes — three original, three corrected |
| All original programs compile | Yes, with intentional warnings and `exit_code=0` |
| All corrected programs compile | Yes, no diagnostics, `exit_code=0` |
| Original defects detected by ASan | Yes — SEGV, heap-use-after-free and double-free |
| Corrected programs under ASan | No ASan errors; all normal runs `exit_code=0` |
| Allocation-failure path tested | Yes — safe error message, `exit_code=1`, no invalid access |
| GDB verification | Breakpoint at `main()` and normal termination |
| Evidence preserved | Yes — separate logs for compilation, corrected ASan, original ASan and GDB |
| GitHub publication | Yes — public repository created and files pushed |

## 12. Conclusion

The experiment demonstrated that the three most common heap-management defects are easy to introduce and potentially severe, but also straightforward to prevent with disciplined coding habits. Checking every allocation result converts a possible crash into controlled error handling. Completing all operations before `free()` and immediately setting the pointer to `NULL` eliminates use-after-free. Centralising deallocation in a NULL-aware helper guarantees that memory is released exactly once.

Compiler warnings identified the unsafe patterns statically, and AddressSanitizer confirmed them dynamically with precise source-line diagnostics. The corrected implementations passed cleanly under the same instrumentation. GDB additionally verified normal program flow through `main()`. The complete source code, genuine evidence, screenshots and documentation have been committed to the public GitHub repository, making the submission reproducible and auditable.
