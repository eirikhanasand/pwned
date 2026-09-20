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
assert all(row['source']['lines'] == row.get('rawOutput', row['output'])['lines'] and row['source']['newlines'] == row.get('rawOutput', row['output'])['newlines'] for row in converted)
assert all(not row.get('deduplicated') or (row['lineMap']['bytes'] == row['source']['lines'] * 8 and row['output']['lines'] + row['duplicateHashesRemoved'] == row['source']['lines']) for row in converted)


def name(value):
    return value.replace('`', '&#96;').replace('|', '&#124;').replace('\n', '\\n').replace('\r', '\\r')


header = f"Snapshot: {summary['updatedAt']}\n\n"
source_note = 'Username-only files were removed and short inventory files were merged into small.txt, with recoverable originals.' if summary.get('sourceInventoryNormalized') else 'Original plaintext files are unchanged.'
if summary.get('originalFilesDeleted'):
    source_note += f" {summary['originalFilesDeleted']:,} original plaintext files were permanently removed after verification; hashes cannot reconstruct their plaintext."
lines = ['# Converted hash files\n\n', header, source_note + ' These are verified hash files in `/home/hanasand/pwned/hash-inventory/files`. Full hash counts are checked before deduplication; original-line maps preserve every occurrence.\n\n', '| Original file | Original lines | Verified before dedupe | Stored hashes | Repeats removed | Original deleted | Finalization blocker |\n|---|---:|---:|---:|---:|---|---|\n']
for row in converted:
    lines.append(f"| `{name(row['file'])}` | {row['source']['lines']:,} | {row.get('rawOutput', row['output'])['lines']:,} | {row['output']['lines']:,} | {row.get('duplicateHashesRemoved', 0):,} | {'Yes' if row.get('originalDeleted') else 'No'} | {name(row.get('finalizationBlocked', ''))} |\n")
(folder / 'converted.md').write_text(''.join(lines))
lines = ['# Files remaining\n\n', header, '| File | Status | Lines (if scanned) | Required hash bytes (if known) |\n|---|---|---:|---:|\n']
for row in remaining:
    lines.append(f"| `{name(row['file'])}` | {row['status']} | {row.get('source', {}).get('lines', '—')} | {row.get('expectedOutputBytes', '—')} |\n")
(folder / 'remaining.md').write_text(''.join(lines))
lines = ['# Matching source files\n\n', header, 'Groups share source byte counts and SHA-256 checksums. Byte-for-byte comparison is also performed when both originals remain available. This list is partial while the scan is running; it covers inventory text files, not excluded archives or metadata. See converted.md for original-file deletion status.\n\n']
for index, group in enumerate(duplicates, 1):
    lines.append(f"## Group {index} — {group['bytesEach']:,} bytes per file\n\n")
    lines.extend(f"- `{name(file)}`\n" for file in group['files'])
    lines.append('\n')
(folder / 'duplicates.md').write_text(''.join(lines))
if summary.get('sourceInventoryNormalized') and (folder / 'cleanup.json').exists():
    cleanup = json.loads((folder / 'cleanup.json').read_text())
    lines = ['# Inventory cleanup\n\n', f"Removed {len(cleanup['usernameFilesRemoved'])} username-only files from the active inventory. Merged {len(cleanup['mergedFiles'])} short inventory files into `small.txt` ({cleanup['smallLines']} lines), preserving duplicate entries.\n\n", '## Recoverable originals\n\n']
    lines.extend(f"- `{name(path)}`\n" for path in cleanup.get('previousBackupDirectories', []) + [cleanup['backupDirectory']])
    lines.append('\n## Removed username files\n\n')
    lines.extend(f"- `{name(file)}`\n" for file in cleanup['usernameFilesRemoved'])
    lines.append('\n## Files merged into small.txt\n\nOriginal line order is preserved within each range. Empty files contribute no lines.\n\n| Original file | Lines before | Lines contributed | Lines in small.txt |\n|---|---:|---:|---|\n')
    for row in cleanup['mergedFiles']:
        count = row.get('lineCount', 1)
        location = f"{row['smallLine']}–{row['smallLine'] + count - 1}" if count else '—'
        lines.append(f"| `{name(row['file'])}` | {count} | {count} | {location} |\n")
    lines.append('\n## Mixed lists left unchanged\n\n')
    lines.extend(f"- `{name(file)}`\n" for file in cleanup['mixedListsPreserved'])
    (folder / 'cleanup.md').write_text(''.join(lines))
print(f"Verified report snapshot: {len(converted):,} converted, {len(remaining):,} remaining, {len(duplicates):,} duplicate groups; all pre-deduplication line counts match; {summary.get('deduplicatedFiles', 0):,} files deduplicated, {summary.get('originalFilesDeleted', 0):,} originals deleted.")
