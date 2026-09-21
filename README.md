# Password hash inventory

The legacy plaintext HTTP/WebSocket lookup service has been retired. This
repository contains the verified SHA-1 conversion, per-file deduplication and
original-line provenance tooling. See [the inventory guide](scripts/hash-inventory.md).

The unsplit master is migrating to an [in-memory compact SHA-1 index](scripts/compact-inventory.md)
with an 800 GB/no-swap limit and disk-space pause/resume. The old split-based
converter is paused; do not restart it. The new builder retains the original
until the complete saved index has been verified.

Production conversion uses `--deduplicate --delete-verified-originals`: verify
the full hash count before deduplication, verify saved unique hashes and their
line map, then delete that file's plaintext immediately. Previously converted
files are finalized first in the existing smallest-first order. Original
deletion is permanent; earlier cleanup backups are not touched.
