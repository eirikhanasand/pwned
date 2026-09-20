#!/usr/bin/env python3
"""Render a downloaded, consistent metadata snapshot as readable file lists."""
import json
from pathlib import Path
import sys

folder = Path(sys.argv[1])
summary, converted, remaining, duplicates = [json.loads((folder / f'{name}.json').read_text()) for name in ['summary', 'converted', 'remaining', 'duplicates']]
assert len(converted) == summary['convertedFiles']
assert len(remaining) == summary['remainingFiles']
assert len(duplicates) == summary['duplicateGroups']
assert sum(row['source']['lines'] for row in converted) == summary['inputLinesConverted']
assert all(row['source']['lines'] == row['output']['lines'] and row['source']['newlines'] == row['output']['newlines'] for row in converted)


def name(value):
    return value.replace('`', '&#96;').replace('|', '&#124;').replace('\n', '\\n').replace('\r', '\\r')


header = f"Snapshot: {summary['updatedAt']}\n\n"
source_note = 'Username-only files were removed and single-entry password files were merged into small.txt, with recoverable originals.' if summary.get('sourceInventoryNormalized') else 'Original plaintext files are unchanged.'
lines = ['# Converted hash files\n\n', header, source_note + ' These are verified hash copies in `/home/hanasand/pwned/hash-inventory/files`.\n\n', '| Original file | Lines before | Lines after | Duplicate of |\n|---|---:|---:|---|\n']
for row in converted:
    lines.append(f"| `{name(row['file'])}` | {row['source']['lines']:,} | {row['output']['lines']:,} | {name(row.get('duplicateOf', ''))} |\n")
(folder / 'converted.md').write_text(''.join(lines))
lines = ['# Files remaining\n\n', header, '| File | Status | Lines (if scanned) | Required hash bytes (if known) |\n|---|---|---:|---:|\n']
for row in remaining:
    lines.append(f"| `{name(row['file'])}` | {row['status']} | {row.get('source', {}).get('lines', '—')} | {row.get('expectedOutputBytes', '—')} |\n")
(folder / 'remaining.md').write_text(''.join(lines))
lines = ['# Identical source files\n\n', header, 'Files in each group were verified byte-for-byte identical. No originals were deleted. This list is partial while the scan is running; it covers inventory text files, not excluded archives or metadata.\n\n']
for index, group in enumerate(duplicates, 1):
    lines.append(f"## Group {index} — {group['bytesEach']:,} bytes per file\n\n")
    lines.extend(f"- `{name(file)}`\n" for file in group['files'])
    lines.append('\n')
(folder / 'duplicates.md').write_text(''.join(lines))
print(f"Verified report snapshot: {len(converted):,} converted, {len(remaining):,} remaining, {len(duplicates):,} duplicate groups; all converted line counts match.")
