# Hash inventory conversion

`hash-inventory.py` runs the native worker smallest-file-first, breaking ties by
relative path. Mount the source read-only and write to a separate destination.
It includes every regular `.txt` file, including top-level lists, but excludes
`lookup.txt`, hidden metadata directories, symlinks, archives and non-text files.
`inventory.json` records the exact input snapshot and all exclusions.

Each source record becomes one uppercase SHA-1 record in `files/<path>.sha1`.
The file name and line order preserve provenance. Blank records are hashed;
only the line terminator is removed (LF and an immediately preceding CR, or a
trailing CR on the last record). No trimming, decoding, sorting or line
deduplication takes place. A missing final LF remains missing. Both logical
record counts and literal LF counts are verified, including empty files.

The worker verifies the saved output size, line counts and SHA-256 checksum
before atomic publication. Original files are never overwritten or deleted.
Complete-file duplicates require equal sizes and SHA-256 checksums **and** a
byte-for-byte comparison. Identical converted files share disk blocks through
hard links; their separate file names and counts remain in the reports.

Reports are updated at least every 30 seconds and at exit:

- `summary.json`: progress, resource limits, verification totals and state.
- `converted.json`: every verified hash file and before/after counts.
- `remaining.json`: every pending, blocked or unfinished source.
- `duplicates.json`: byte-identical source-file groups (no deletion).
- `journal.jsonl`: durable per-file results for resumption.

Resume with the same source, destination and options. Completed output files
are reread and verified; changed sources or corrupt outputs stop the run.
An unrecorded published output also stops for inspection rather than silently
trusting it. Space-blocked files are still scanned for duplicate detection.
The process holds an exclusive destination lock to prevent concurrent writers.

Compile on Linux with OpenSSL development headers and OpenMP:

```sh
g++ -O3 -std=c++17 -fopenmp -static -Wno-deprecated-declarations scripts/hash-inventory-worker.cpp -lcrypto -o worker
```

Run inside a cgroup with at most **500,000,000,000 bytes** of RAM and no swap.
The driver refuses an unlimited cgroup. A 150,000,000,000-byte free-space
reserve is the default; exact output sizes are calculated before writing and
space is checked again for each in-memory batch. The worker uses mapped source
pages and in-memory output batches, not plaintext temporary files. All process
memory is released on exit; no global cache-flush commands are used.

The generated inventory is not yet a prefix-search index. Do not point the
legacy plaintext/binary-search service at it: SHA-1 records are deliberately
kept in original line order, not hash-sorted order.

## Inventory cleanup

Pause the converter before running `consolidate-inventory.py`. Preview first,
then use `--apply` to remove username-only files and merge single-record
password lists into `small.txt`. Duplicates are preserved. Mixed username/password
lists and identified hash test vectors are left unchanged. Original sources,
obsolete hashes and previous metadata are moved/copied into the specified
recoverable backup, and `cleanup.json` maps each original file to its new line.
Mount the source, report and backup directories through one common parent
bind mount: separate bind mounts prevent the atomic rename used for backups,
even when their host directories share a device. Never overwrite existing
`small.txt` or reuse a previous backup directory.

The converter now handles SIGINT/SIGTERM by finishing the current file and
pausing at a file boundary. Resume the existing container after cleanup with
the same resource limits. Its reports reflect the revised inventory.
