# Password hash inventory

The legacy plaintext HTTP/WebSocket lookup service has been retired. This
repository contains the verified SHA-1 conversion, per-file deduplication and
original-line provenance tooling. See [the inventory guide](scripts/hash-inventory.md).

Production conversion uses `--deduplicate --delete-verified-originals`: verify
the full hash count before deduplication, verify saved unique hashes and their
line map, then delete that file's plaintext immediately. Previously converted
files are finalized first in the existing smallest-first order. Original
deletion is permanent; earlier cleanup backups are not touched.
