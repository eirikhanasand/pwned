# Compact, in-memory inventory build

The incomplete numeric all-in-one splits have been retired. Do not restart the
old `pwned-hash-inventory-349ee56` converter or recreate plaintext splits. Its
remaining non-split datasets, conversion receipts and cleanup backups remain
separate from this master-file build.

`build-compact-inventory.cpp` builds one original source file into the prefix
index read by `compact_index.py`. Each in-memory record occupies exactly 25
bytes: the full 20-byte SHA-1 and a 5-byte, one-based original line number.
The original filename is stored once in the catalog. Duplicate hashes share
an index entry while retaining all original line ranges and occurrence counts.
Line numbers must fit in 40 bits; oversized lines/blocks fail explicitly.

For the master profiled on 20 September 2026:

- Original: `all_in_one/all_in_one_sorted.txt`, 305,105,563,518 bytes.
- Logical lines and LF terminators: 26,921,656,388 each.
- SHA-256: `f83a01a3d1c057473b36de871d65546d060c81a31e1e658203c299e7e34c2dfe`.
- Packed records: 673,041,409,700 bytes, plus bounded buffers and a temporary
  3.37 GB line-permutation verification bitmap.
- User-approved container maximum: **800,000,000,000 bytes, no swap**.
- Disk reserve remains **150,000,000,000 bytes**.

## Verification and space handling

1. Read the source sequentially using bounded buffers, compute its SHA-256,
   hash every logical line in parallel and record its original line number.
   Normalize only LF and the immediately preceding CR, or a trailing CR on the
   final unterminated record. Blank lines and arbitrary bytes are preserved.
2. Compare source bytes, SHA-256, logical lines and LF count against the profile
   **before** deduplication. Check the source inode, size and timestamps.
3. Partition and sort records in place; no second full-size sorting array and
   no disk sorting runs. Verify strict hash/line order and every original line
   appearing exactly once, using a bitmap.
4. Write compressed prefix blocks to an exclusive `.partial` file, periodically
   syncing to disk. Every write checks available space above the reserve.
   If space runs short, or a write reports ENOSPC/EDQUOT, the same process waits
   and retries. It retains the records in RAM, reports `waiting_for_disk`, and
   resumes automatically after space becomes available. Nothing is discarded
   to make room, and the source is rechecked after each pause.
5. Sync the whole saved index. Reread its header and every compressed block,
   decode it and compare it against the in-memory hashes and exact provenance.
   Verify total occurrences and unique hashes, compute the saved SHA-256 and
   recheck the unchanged source. Only then publish without replacing an existing
   file. The builder never deletes the source.

The original remains necessary until the complete saved replacement is verified.
RAM is not a durable backup: stopping/restarting the process or host loses the
in-memory work and requires rebuilding. The original remains safe in that case.
Existing partial files block automatic restart and must be inspected explicitly.
Do not run another converter or restart a waiting container to resolve low space.
Memory is returned when the process exits; do not globally flush filesystem caches.

## Build and tests

On Linux with OpenSSL, zlib and OpenMP development libraries:

```sh
g++ -O3 -std=c++17 -fopenmp -static -Wno-deprecated-declarations scripts/build-compact-inventory.cpp -lcrypto -lz -o compact-builder
```

Arguments, in order:

```text
SOURCE OUTPUT CATALOG_NAME LINES LF_COUNT BYTES SHA256 MEMORY_BYTES RESERVE_BYTES THREADS
```

The output directory must exist. Mount the input read-only and the dedicated
output directory writable. Run under a cgroup enforcing the configured RAM cap
and the same memory+swap cap, with no network and no core dumps. The worker's
budget check is not a substitute for the cgroup limit. The output lock prevents
concurrent builders for the same release.

Use `-DPWNED_TESTING` only for the test binary, then run:

```sh
python3 tests/build-compact-inventory-test.py /path/to/test-binary
python3 tests/compact-index-test.py
```

The test-only build can simulate available space through `PWNED_TEST_SPACE_FILE`;
production builds do not include that override. Tests cover exact SHA-1 values,
line provenance and counts, duplicate runs, CRLF/binary/large records, input batch
boundaries, 40-bit line encoding, rejected source changes, memory limits,
exclusive output/locks, and pauses both before and during output writing.

## Live handoff without rehashing (21 September 2026)

The original worker lacks a runtime early-source-release option. The separate
Linux `resume-compact-inventory.cpp` receiver can continue its partial index using
the original process's already checked, sorted records. **Never kill, restart or
resume the stopped donor:** its anonymous RAM is the only copy of unwritten
records after early source deletion. The on-disk index format is unchanged.

The receiver runs unprivileged inside the donor's existing 800 GB/no-swap cgroup.
A short-lived 64 MiB helper with SYS_PTRACE and DAC_OVERRIDE checks the donor's
PID-namespace identity, stopped state and exact anonymous mapping, then passes a
read-only memory descriptor over a private Unix socket and exits. It never writes
process memory. The receiver reads bounded 8 MiB chunks and at most a 64 MiB
prefix bucket; it does not allocate a second full record array.

The receiver reconstructs the unfinished prefix directory by decoding existing
self-delimiting zlib blocks and comparing every complete block against donor RAM.
Existing complete blocks are reused unchanged. Only an incomplete trailing write
may be truncated and rewritten from RAM. Corruption causes failure, not silent
discard. After appending the remaining blocks, it rereads and verifies the entire
saved index against RAM before publishing, retaining exact filenames, lines and
counts. The original source's final snapshot check is deliberately skipped under
the user's early-deletion authorization; its initial checksum, byte/line counts,
sort and line-permutation checks were already completed by the donor.

`handoff-master-inventory.py start` is intentionally scoped to this exact Inspur
master, source snapshot and named donor. It records the identity and memory
address durably, stops only the original writer, and starts the receiver. It does
not delete the source. The separate `release-source --allow-early-source-delete`
command requires all previously completed blocks to be verified and at least
512 MiB of additional output, then fsyncs output and records deletion intent.
Because the donor's open descriptor and single-file bind mount retain the inode,
it must truncate the verified exact original before unlinking to actually free
305,105,563,518 bytes. This is permanent: a host/donor failure before completion
requires the user's external backup. Other datasets and backups are untouched.

The receiver retains a 100 GB free-space floor (the original used 150 GB). The
projected final space after original reclamation is about 120 GB; unchanged
external disk usage is not guaranteed. It waits with RAM retained if that floor
is reached. No global caches are flushed.

Monitor `master.pwnidx.handoff.status.json`, `.handoff.log`, `.handoff.exit.json`
and the durable `.handoff.json` receipt, not the frozen donor's old status. A
receiver failure does not release donor RAM. Inspect the error and repair/restart
only the receiver if appropriate; it rescans/reuses complete saved blocks, with
no rehash or sort. Never launch a second concurrent receiver. Do not remove the
donor until exit code 0, full saved-index verification and reader checks establish
a durable replacement; then stopping the donor releases its RAM.

Build the receiver with the same native flags/libraries as the original. Real
Docker process-handoff tests are in `tests/compact-handoff-test.py`; these include
source removal, incomplete tails, corruption, dense blocks, disk waits, and
receiver-only restart with donor RAM retained. The fixture donor is test-only.

This builder does not integrate the index with the public API or UI. Completion
of a hash build is not evidence that the website is using the new inventory.
