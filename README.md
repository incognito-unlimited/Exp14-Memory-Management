# Lab 2 — Memory Management Error Identification and Remediation

**Subject:** Secure Coding and Vulnerabilities  
**Experiment:** Lab 2 — Memory Management Error Identification and Remediation  
**Student:** Aditey Mehra  
**University:** K.R. Mangalam University  
**Roll Number:** 2301730266  
**Programme:** B.Tech Computer Science and Engineering  
**Specialisation:** Artificial Intelligence and Machine Learning  
**Section:** D  
**Semester:** 7  

**GitHub repository:** https://github.com/incognito-unlimited/Exp14-Memory-Management

---

## Aim

To identify, analyse, reproduce and remediate three common memory-management defects in C — an unchecked `malloc()` return value, a heap use-after-free and a double-free — and to verify the corrected implementations with compiler warnings and AddressSanitizer.

## Objectives

1. Study how dynamic memory allocation failures occur and why the result of `malloc()` must be validated.
2. Understand the lifecycle of heap memory: allocate → use → free → invalidate the pointer.
3. Demonstrate use-after-free and double-free with deliberately vulnerable programs.
4. Implement corrected versions that check allocations, avoid post-free access, reset pointers to `NULL` and free each allocation exactly once.
5. Compile all programs with strict warnings and AddressSanitizer.
6. Record genuine compiler, AddressSanitizer and GDB output as evidence.
7. Document the classification, impact and remediation of each error.
8. Publish the complete work on GitHub.

## Source provenance

No faculty-provided source files and no separate reference-report source snippets were present in the workspace when this experiment was performed. Therefore, the three vulnerable programs in `original/` were written specifically for this lab from the requirements in the experiment brief. Each program is independent and contains only the intended defect. The matching programs in `fixed/` preserve the same scenario while applying the remediation.

## Vulnerabilities studied

| # | File | Error | Primary weakness | What goes wrong |
|---|------|-------|------------------|-----------------|
| 1 | `original/snippet1.c` | Unchecked `malloc()` return value | CWE-476 / CWE-754 | `malloc(SIZE_MAX)` fails and returns `NULL`; the program writes through the unchecked pointer. |
| 2 | `original/snippet2.c` | Heap use-after-free | CWE-416 | The program reads and writes a 48-byte heap buffer after `free()`. |
| 3 | `original/snippet3.c` | Double-free | CWE-415 | The same 16-byte allocation is released twice because the pointer is not invalidated after the first `free()`. |

### 1. Unchecked `malloc()` return value

`malloc()` returns `NULL` when the requested block cannot be allocated. The original program requests `SIZE_MAX` bytes to make that failure deterministic, then calls `strcpy()` on the returned pointer without checking it. Under AddressSanitizer with `allocator_may_return_null=1`, the failed allocation is allowed to return `NULL`, and the subsequent write produces a `SEGV on unknown address 0x000000000000`.

Important: with an ordinary small allocation the allocator will normally succeed, so this defect may not be reproduced by a casual run. The absence of a crash is not proof that the check is unnecessary; allocation failure depends on request size, memory pressure, limits and allocator behaviour. The corrected program provides a `--simulate-oom` option so the failure path can be tested deliberately.

### 2. Heap use-after-free

After `free(message)`, the allocation belongs to the allocator. The pointer value still exists but dereferencing it is undefined behaviour. The original program prints the buffer and then writes `message[0] = 'X'` after the release. AddressSanitizer reports a `heap-use-after-free` write and shows both the freeing stack and the original allocation stack.

### 3. Double-free

The original program calls `free(scores)`, prints a message and calls `free()` again with the same stale address. A second release corrupts allocator metadata and can enable arbitrary-write primitives in real exploits. AddressSanitizer reports `attempting double-free` and identifies both the first and second release sites. The second release is placed in a small `noinline` helper so an optimising compiler does not remove the deliberately undefined operation before the runtime can observe it.

## Remediation techniques applied

- Every `malloc()` result is checked against `NULL` before any access.
- On allocation failure, an error message is written to `stderr` and the program exits safely with `EXIT_FAILURE`.
- All reads and writes are completed before `free()`.
- Immediately after `free()`, the pointer is set to `NULL`.
- A guarded helper function skips duplicate deallocation when the pointer is already `NULL`.
- All six programs are compiled with `-Wall -Wextra -std=c11 -g -O1 -fsanitize=address -fno-omit-frame-pointer`.

## Repository structure

```text
Lab2-Memory-Management/
├── original/
│   ├── snippet1.c                 # unchecked malloc()
│   ├── snippet2.c                 # heap use-after-free
│   └── snippet3.c                 # double-free
├── fixed/
│   ├── snippet1_fixed.c
│   ├── snippet2_fixed.c
│   └── snippet3_fixed.c
├── evidence/
│   ├── asan_results.txt           # corrected-program ASan output
│   ├── original_asan_results.txt  # original-program ASan diagnostics
│   ├── compilation_results.txt    # all six compilations
│   ├── gdb_results.txt            # GDB breakpoint and normal termination
│   └── screenshots/               # genuine terminal/browser screenshots
├── report/
│   ├── error_classification.md
│   ├── Lab_Report.md
│   └── Lab_Report.docx
├── README.md
└── .gitignore
```

Build binaries are written to `build/` and are excluded by `.gitignore`.

## Prerequisites

- Linux environment with GCC and AddressSanitizer (verified on WSL 2 / Ubuntu 26.04.1, GCC 15.2.0).
- GNU GDB (verified with GDB 17.1).
- `make` is **not** required; the compile commands are listed below.
- Optional: Git and GitHub CLI for publication.

## Compilation

From the repository root:

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

Actual compiler output is preserved in `evidence/compilation_results.txt`. All six compilations exited `0`. The original programs intentionally produce warnings (`-Walloc-size-larger-than`, `-Wuse-after-free`); the three corrected programs compile without diagnostics.

## Execution

```bash
./build/snippet1_fixed
./build/snippet2_fixed
./build/snippet3_fixed

# Controlled allocation-failure path for program 1
./build/snippet1_fixed --simulate-oom
```

## AddressSanitizer testing

```bash
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:allocator_may_return_null=1:print_stacktrace=1

./build/snippet1_fixed
./build/snippet2_fixed
./build/snippet3_fixed
./build/snippet1_fixed --simulate-oom

# Deliberately vulnerable originals
./build/snippet1
./build/snippet2
./build/snippet3
```

`allocator_may_return_null=1` is required so that the oversized `malloc()` returns `NULL` instead of causing ASan to abort at the allocation site.

### Actual corrected-program results

| Program | ASan result | Exit code |
|---------|-------------|-----------|
| `snippet1_fixed` | No ASan error; 64-byte allocation used and freed | 0 |
| `snippet2_fixed` | No ASan error; all access completed before free | 0 |
| `snippet3_fixed` | No ASan error; duplicate free skipped by NULL guard | 0 |
| `snippet1_fixed --simulate-oom` | ASan advisory warning only; application printed its error and exited safely | 1 |

See `evidence/asan_results.txt` for the complete, unedited output.

### Actual original-program diagnostics

| Program | AddressSanitizer diagnostic |
|---------|-----------------------------|
| `snippet1` | `ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000` caused by the write through the NULL pointer |
| `snippet2` | `ERROR: AddressSanitizer: heap-use-after-free ... WRITE of size 1` |
| `snippet3` | `ERROR: AddressSanitizer: attempting double-free` |

See `evidence/original_asan_results.txt`. Original and corrected results are stored in separate files.

## GDB verification

GDB was available and was used on `build/snippet1_fixed`:

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

`detect_leaks=0` avoids LeakSanitizer's known limitation under `ptrace`. The genuine session shows:

- `Breakpoint 1 at 0x1289: file fixed/snippet1_fixed.c, line 18.`
- `Breakpoint 1, main (...) at fixed/snippet1_fixed.c:18`
- program output from the corrected program
- `[Inferior 1 (process 512) exited normally]`

Full output: `evidence/gdb_results.txt`.

## Screenshots

All screenshots are genuine captures of the prepared terminal windows or the published GitHub repository:

| File | Content |
|------|---------|
| `evidence/screenshots/01_project_structure.png` | Project directory and source files |
| `evidence/screenshots/02_original_compilation.png` | Compilation of all original programs |
| `evidence/screenshots/03_fixed_compilation.png` | Compilation of all corrected programs |
| `evidence/screenshots/04_asan_clean_run.png` | AddressSanitizer clean runs |
| `evidence/screenshots/05_original_asan_errors.png` | Original vulnerability diagnostics |
| `evidence/screenshots/06_gdb_verification.png` | GDB execution |
| `evidence/screenshots/07_github_repository.png` | GitHub repository after pushing |

## Reports

- `report/error_classification.md` — concise classification and impact analysis.
- `report/Lab_Report.md` — full laboratory report in Markdown.
- `report/Lab_Report.docx` — editable academic-format final report.

## Result

All three original programs demonstrated the intended defect. All three corrected programs compiled cleanly, ran under AddressSanitizer without an error report and exited `0`. The controlled allocation-failure test for program 1 exited with `1` after printing a clear diagnostic, with no invalid memory access. GDB confirmed a breakpoint at `main()` and normal termination.

## Limitations / notes

- No faculty source files or supplied reference-report snippets were available; the vulnerable programs are original implementations of the specified errors.
- An unchecked small `malloc()` may succeed in an ordinary run, so the first defect is demonstrated with `SIZE_MAX` and `allocator_may_return_null=1`.
- The final DOCX was generated with consistent academic styling because no separate editable template file was supplied in the workspace.

## GitHub repository

https://github.com/incognito-unlimited/Exp14-Memory-Management
