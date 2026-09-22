# Password hash inventory

The legacy plaintext HTTP/WebSocket lookup service has been retired. This
repository contains the verified SHA-1 conversion, per-file deduplication and
original-line provenance tooling. See [the inventory guide](scripts/hash-inventory.md).

The unsplit master has been converted to a verified [compact SHA-1 index](scripts/compact-inventory.md).
The master contains 26,921,656,388 hashes with original file/line provenance.
Its original was removed early with explicit authorization; saved records were
then fully checked against the retained sorted RAM before that RAM was released.
The old split-based converter remains retired; do not restart it.

`compose.prefix.yml` serves the completed master read-only on the private
application network and host loopback port 8099. `/range/ABCDE` accepts exactly
five hexadecimal characters, returning the original compressed prefix block
with its file catalog. It never accepts a password or complete hash. The
`PWNPRF01` wire envelope is documented in `scripts/serve-compact-index.py`.
The finalized and remaining inventories are physically consolidated into
`compact-inventory/deduplicated/sources.pwnidx`: one stored occurrence per
hash/source, with matching unsorted originals preferred over sorted copies.
Empty source entries are removed. The lookup serves these stored records directly;
it does not suppress or deduplicate results. Historical receipts retain the
before/after evidence and original line references.

Production conversion uses `--deduplicate --delete-verified-originals`: verify
the full hash count before deduplication, verify saved unique hashes and their
line map, then delete that file's plaintext immediately. Previously converted
files are finalized first in the existing smallest-first order. Original
deletion is permanent; earlier cleanup backups are not touched.
