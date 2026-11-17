# Error Classification — Lab 2

**Student:** Aditey Mehra  
**Roll Number:** 2301730266  
**Subject:** Secure Coding and Vulnerabilities  
**Experiment:** Memory Management Error Identification and Remediation  

## Classified error table

| ID | Vulnerable source | Error class | CWE | Exact programming mistake | Security impact | Remediation | Evidence |
|----|-------------------|-------------|-----|---------------------------|-----------------|-------------|----------|
| E1 | `original/snippet1.c` | Unchecked allocation result leading to NULL-pointer dereference | CWE-476 (NULL Pointer Dereference), CWE-754 (Improper Check for Unusual or Exceptional Conditions) | `malloc(SIZE_MAX)` is called and its return value is assigned to `buffer`, but the program never tests whether `buffer == NULL` before `strcpy()` writes through it. | Denial of service through process crash. In a larger program, an unchecked allocation failure can also corrupt state, bypass error handling or turn a recoverable resource shortage into an exploitable crash path. | Check `malloc()` result immediately; print an error to `stderr`; exit safely with `EXIT_FAILURE`; only access memory after a successful check; free and set pointer to `NULL`. | `original_asan_results.txt`: `SEGV on unknown address 0x000000000000`; `asan_results.txt`: graceful `--simulate-oom` exit. |
| E2 | `original/snippet2.c` | Heap use-after-free | CWE-416 (Use After Free) | `free(message)` is followed by `printf("%s", message)` and `message[0] = 'X'`; the stale pointer is dereferenced for both read and write. | Reading freed heap memory leaks stale or attacker-influenced data; writing to freed memory can corrupt allocator metadata and, in exploitable cases, lead to arbitrary code execution. | Complete all reads and writes before `free()`; release memory once; set pointer to `NULL`; never dereference it afterwards. Use a post-free `NULL` guard. | `original_asan_results.txt`: `heap-use-after-free ... WRITE of size 1`. |
| E3 | `original/snippet3.c` | Double-free | CWE-415 (Double Free) | The same pointer value `scores` is passed to `free()` twice because it is not set to `NULL` after the first release. | Heap metadata corruption, process crash and potential arbitrary-write or code-execution primitive if an attacker can control allocator state between the two frees. | Free exactly once through a guarded helper; set the pointer to `NULL` in the same operation; make subsequent release attempts harmless no-ops. | `original_asan_results.txt`: `attempting double-free`. |

## Detailed analysis

### E1 — Unchecked `malloc()` return value

`malloc()` is allowed to fail. It signals failure by returning `NULL`, and every caller is responsible for checking that value. The original code assumes success and writes a string into the returned address. Because the request is deliberately `SIZE_MAX`, the allocator cannot satisfy it and returns `NULL`; the write then faults at address zero.

A normal small allocation would usually succeed, so this bug is often invisible in casual testing. Dependable testing either forces the failure path or inspects the code statically. The corrected implementation checks the result before every use and supports `--simulate-oom` to exercise the failure deterministically. It also frees the successful allocation and sets the pointer to `NULL`.

### E2 — Heap use-after-free

A pointer returned by `malloc()` stops being valid for application use as soon as `free()` is called on it. The original program violates this rule by printing the buffer and then modifying it after release. AddressSanitizer poisons the freed region and reports the first invalid access with both the free stack and the allocation stack.

The corrected program performs all string operations and computes the length while the allocation is live. It then frees the buffer, immediately assigns `NULL` to the pointer and only checks the pointer value — never its pointee — after the release.

### E3 — Double-free

Calling `free()` twice with the same address violates the allocator's ownership contract. The original program leaves the stale address in `scores` after the first release and passes it to a second `free()`. A `noinline` helper is used only to keep the deliberate second release visible at `-O1`.

The corrected program centralises deallocation in `release_once(int **pointer)`. The helper checks the pointer and the pointed-to value, calls `free()` exactly once, sets the caller's pointer to `NULL`, and treats any later call as a harmless no-op.

## Cross-cutting remediation principles

1. Treat every allocation as fallible.
2. Keep allocation and ownership explicit; one owner performs one release.
3. Set pointers to `NULL` in the same statement or helper that frees them.
4. Never dereference a pointer after its release.
5. Compile with warnings enabled and run with AddressSanitizer during development and testing.
6. Keep vulnerable and fixed implementations separate so evidence remains auditable.
