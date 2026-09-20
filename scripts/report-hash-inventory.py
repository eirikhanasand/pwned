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
source_note = 'Username-only files were removed and short inventory files were merged into small.txt, with recoverable originals.' if summary.get('sourceInventoryNormalized') else 'Original plaintext files are unchanged.'
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
print(f"Verified report snapshot: {len(converted):,} converted, {len(remaining):,} remaining, {len(duplicates):,} duplicate groups; all converted line counts match.")
