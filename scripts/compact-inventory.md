# Compact, in-memory inventory build

## Remaining-source RAM batch

`build-compact-batch.cpp` reuses the native packed-record builder and prefix
format, mapping global sort ordinals back to explicit filenames/local lines.
`run-remaining-inventory.py` excludes the already-covered master and finalized
overlay, profiles remaining originals smallest first, checks inventory snapshots,
and drives a bounded RAM build. It creates one additional index, not a database
row per occurrence or a new plaintext/hash-text intermediate. The sixteen
unfinalized sources are rehashed from their retained originals; neither completed
index is rehashed or sorted. Each output retains all original occurrences while
deduplicating stored hashes. Per-file original/unique counts are in the receipt.

Production must use a no-swap container, a bounded `/work` tmpfs and a matching
memory cap. Source retirement is disabled until the complete RAM index has been
reread, every compressed block/provenance record compared to the sorted records,
and its checksum independently verified. `--release-sources-from-ram` explicitly
permits deleting checked originals smallest-first if needed to fit the durable
copy above the configured reserve. This option requires tmpfs and cgroup swap=0.
Each exact path is rechecked for its original snapshot, checksum and line count,
with a durable deletion intent before unlink. **RAM-only retirement risks loss
on host/container restart until disk publication succeeds.** Keep the container
alive on both success and errors; never use `--rm` for production or restart it
to clear a disk wait. The publisher preserves the RAM file and resumes writes.

The disk replacement gets a full saved checksum/header/count check, fsync and
atomic publication; only then are any remaining originals retired. Immutable
old receipts stay as audit history; `remaining.status.json`, `remaining.plan.json`,
`remaining.retirement.json` and `remaining.report.json` describe the new storage.
Legacy text hashes/maps are kept until live index integration is checked.
The packed sort array is released at builder exit; retain only the compressed
RAM result until live checks pass. Do not run the old converter against this
retired inventory, or mistake its historical remaining.json for current state.

Compile the batch with the same flags/libraries as the native builder. Run
`tests/compact-batch-test.py BATCH_BINARY SCANNER_BINARY`, plus the original
native-builder and publisher regressions. Set `TEST_RAM_RETIREMENT=1` only in
an isolated no-swap tmpfs test container to exercise volatile retirement using
synthetic data and simulated low space.

After checking live results, `retire-compact-inputs.py INVENTORY INDEX --retire`
can remove superseded legacy text hashes/maps. Without `--retire` it only plans
and verifies. It checks the durable index SHA-256 and every exact legacy input
checksum, then journals each deletion in `compacted.json`. Native remaining-batch
receipts cover the sixteen raw legacy hash files: their original source checksums
and pre-dedupe counts must match the earlier conversion, and the original filename
must be in the new catalog. New sources without legacy text hashes are skipped.
Receipts, snapshots and original counts remain available after retirement; the
legacy driver refuses this migrated inventory and import selection skips it.

## Importing previously finalized files

`import-compact-overlay.py INVENTORY OUTPUT` plans a separate PWNIDX01 overlay
from the finalized entries in `converted.json`, smallest original files first.
It does not open or rewrite the master index. `--max-lines` bounds a batch;
the default mode only inspects metadata. `--verify-inputs` checks the selected
hashes and maps in RAM without writing an index. `--build` additionally writes,
rereads and verifies every saved hash, original filename and line before
publishing the overlay and an immutable `.receipt.json`.

Input checks include saved checksums, pre-deduplication line counts, sorted unique
hashes, valid line-map ordinals, and reconstruction of the entire original-order
hash checksum (including an absent final LF). Merged `small.txt` records recover
their original filenames and local line numbers from `cleanup.json`; missing,
overlapping or incomplete provenance fails. No input, backup or original is
deleted by this importer. Verified overlays are not automatically served.

The importer takes the existing inventory lock, bounds its planned memory, and
requires room for a conservative output estimate above the disk reserve. Use a
no-network, no-swap container with a matching memory limit. Its default reserve
is still 150 GB; low disk is not permission to bypass that floor. Any leftover
`.verifying` file or receipt after interruption requires inspection before retry.
Do not rerun a batch under a different output name without checking receipts,
since overlapping overlays would double-count occurrences.

Run `python3 tests/compact-overlay-test.py` for import and corruption regressions.

For constrained disks, a dedicated, size-limited tmpfs may hold the overlay
while it is built and verified. Its pages count toward the builder's no-swap
memory limit. Use `--reserve-bytes 0` only for that explicit RAM destination;
retain all source hashes/maps. Keep the tmpfs-owning container alive afterward:
a verified RAM file is not a durable replacement.

`publish-compact-overlay.py SOURCE TARGET --reserve-bytes BYTES` copies an
already-verified overlay to disk. The source and its `.receipt.json` are
read-only inputs; only a dedicated overlay output directory needs write access.
The publisher requires an explicit free-space floor, checks room for the
remaining copy before writing, and rechecks space while copying. It waits on
low space or ENOSPC rather than restarting the build. Its intent receipt and
`.copy.partial` allow resumption: every saved byte is compared with the source
before appending, and corruption fails without discarding either copy.

The complete saved checksum, index boundaries and unique count are verified
before fsync and atomic publication. `--owner UID` sets the final index uid/gid
when a root helper is needed to read a private tmpfs. The published index is
read-only. Neither the RAM file nor any old hashes/maps are deleted by this
tool. Configure and test the new live overlay before retiring superseded
representations, then release its RAM. The 303-file batch uses a separately
assessed 20GB disk-copy floor; this does not change the master/build defaults.
Run `python3 tests/publish-compact-overlay-test.py` for transfer regressions.
Where a tmpfs cannot be shared with another container, run the publisher on
the host with `--container BUILD_CONTAINER /work/INDEX /disk/INDEX`: it pins the
container ID and reads through Docker's normal exec stream. No `/proc` mount,
privileged helper, host-wide capability or extra large temporary copy is needed.
`tests/publish-compact-overlay-docker-test.py` verifies this path with a small,
disposable RAM-only fixture; never use production data for that test.

### Serving additional indexes

`serve-compact-index.py MASTER --overlay VERIFIED_OVERLAY` accepts up to 16
indexes. Mount each file read-only and list it explicitly; do not mount or serve
an unfinished `.partial`/`.verifying` output. Startup rejects repeated original
filenames across catalogs, so importing the same source twice cannot inflate
counts. Keep `small.txt`'s original filenames, not just its aggregate name.

The service sends saved compressed blocks unchanged. A single index returns
PWNPRF01; multiple disjoint catalogs return PWNPRF02. There is no lookup-time
filtering or deduplication. Limits remain 32 MiB per response, 64 MiB combined
expanded blocks, and 1 MiB catalogs. Corrupt or oversized input fails the query.

### Physical source deduplication

`rewrite-deduplicated-index.py --worker NATIVE --reserve-bytes BYTES OUTPUT INPUT...`
replaces duplicate stored provenance, rather than changing lookup results.
Compile `rewrite-deduplicated-index.cpp` with the original builder's native flags
and libraries. Inputs require verified `.receipt.json` files and remain read-only.
The worker checks their complete SHA-256 checksums against those receipts.

The first pass scans every hash and run, keeps the earliest original line per
hash/file, and discards a `name_sorted.txt` occurrence only when the same hash
exists in `name.txt` in the same directory. Sorted-only passwords survive.
A new compact file catalog omits sources left with no records. The second pass
writes the replacement; the third reconstructs every expected record from the
inputs and compares it to the saved replacement. Publication happens only after
complete verification and fsync. A saved checksum and reconciled before/after
counts are recorded in `.receipt.json`; `.status.json` tracks progress. No input
is deleted by the builder. An error leaves sources and partial output intact;
existing output/partial files prevent accidental overwrite or restart.

Production uses 8 CPUs, a 12 GiB/no-swap cap and a 30 GB free-disk floor. The
already unique, single-file master does not need rewriting: its verified original
occurrence count equals the stored unique count (26,921,656,388). Its original
checksum/count verification receipt remains authoritative. The finalized and
remaining overlays are replaced by `deduplicated/sources.pwnidx`. Deploy this
index through `compose.prefix.yml`, verify the direct reader and live decoder,
and only then run `retire-rewritten-indexes.py --container pwned-index
REPLACEMENT OLD_INDEX... --retire`. Its dry-run default and retirement both check
the full replacement/source checksums and current container mounts; a durable
deletion receipt precedes removal of the exact old indexes.
Historical conversion receipts remain audit history, not active lookup data.
Future imports must undergo this physical normalization before publication.

Tests: `tests/rewrite-deduplicated-index-test.py NATIVE`,
`tests/retire-rewritten-indexes-test.py`, `tests/compact-prefix-service-test.py`,
and `tests/compact-index-test.py`.

## Original master build (historical procedure)

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
