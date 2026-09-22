"""Verify and compact finalized hash files without rehashing or removing inputs.

Default is a metadata-only plan. --build requires sufficient memory and disk;
production must also run inside a no-swap, memory-limited container. The master
index is never opened. Each output is a separate, fully verified PWNIDX01 overlay.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct

from compact_index import Index, build_index

PACKED = struct.Struct('>20sIQ')


def relative(value):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('unsafe inventory path')
    return path


def read_verified(root, name, expected):
    path = root / relative(name)
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('unsafe hash/map path')
    with path.open('rb') as stream:
        if os.fstat(stream.fileno()).st_size != expected['bytes']:
            raise ValueError('saved size mismatch: ' + name)
        data = stream.read(expected['bytes'] + 1)
    if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest().upper() != expected['sha256'].upper():
        raise ValueError('saved checksum mismatch: ' + name)
    return data


def selection(root, max_lines):
    rows = json.loads((root / 'converted.json').read_text())
    registry = root / 'compacted.json'
    compacted = json.loads(registry.read_text()) if registry.exists() else {}
    eligible = sorted((r for r in rows if r.get('deduplicated') and r['file'] not in compacted),
                      key=lambda r: (r['source']['bytes'], r['file']))
    selected, lines = [], 0
    for row in eligible:
        if lines + row['source']['lines'] > max_lines:
            break  # Preserve smallest-first order across batches.
        relative(row['file'])
        lines += row['source']['lines']
        selected.append(row)
    if len({r['file'] for r in selected}) != len(selected):
        raise ValueError('duplicate source name in inventory')
    largest = max((r['output']['bytes'] + r['lineMap']['bytes'] for r in selected), default=0)
    return selected, {
        'selectedFiles': len(selected), 'originalLines': lines,
        'remainingFinalizedFiles': len(eligible) - len(selected),
        'notFinalizedFiles': sum(not r.get('deduplicated') and r['file'] not in compacted for r in rows),
        'compactedFiles': len(compacted),
        'memoryBudgetBytes': lines * 192 + largest * 3 + 256 * 1024**2,
        # Conservative allowance for sparse prefix compression and postings.
        'estimatedMaximumIndexBytes': lines * 100 + 16 * 1024**2,
        'files': [r['file'] for r in selected],
    }


def load_records(root, rows, cleanup):
    catalog, ids, packed = [], {}, []

    def file_id(name):
        relative(name)
        if name in ids:
            raise ValueError('duplicate original filename')
        ids[name] = len(catalog)
        catalog.append(name)
        return ids[name]

    for row in rows:
        source, raw = row['source'], row['rawOutput']
        if any(source[k] != raw[k] for k in ('lines', 'newlines', 'terminated')):
            raise ValueError('pre-deduplication count mismatch: ' + row['file'])
        hashes = read_verified(root, row['outputPath'], row['output'])
        mapping = read_verified(root, row['lineMapPath'], row['lineMap'])
        unique = row['output']['lines']
        if len(hashes) != unique * 41 or len(mapping) != source['lines'] * 8:
            raise ValueError('invalid hash/map record count')
        if not re.fullmatch(rb'(?:[0-9A-F]{40}\n)*', hashes):
            raise ValueError('invalid SHA-1 records')
        digests = [bytes.fromhex(hashes[i:i + 40].decode()) for i in range(0, len(hashes), 41)]
        if any(a >= b for a, b in zip(digests, digests[1:])):
            raise ValueError('hashes are not sorted and unique')

        spans = []
        if row['file'] == 'small.txt':
            if cleanup.get('smallFile') != 'small.txt' or cleanup.get('smallLines') != source['lines']:
                raise ValueError('missing small.txt provenance')
            if cleanup.get('smallSha256', '').upper() != source['sha256'].upper():
                raise ValueError('small.txt source checksum mismatch')
            cursor = 1
            for entry in sorted(cleanup['mergedFiles'], key=lambda e: e['smallLine']):
                count = entry.get('lineCount', 1)
                if count < 0:
                    raise ValueError('negative merged source count')
                if not count:
                    file_id(entry['file'])
                    continue
                if entry['smallLine'] != cursor:
                    raise ValueError('gap or overlap in merged source provenance')
                spans.append((cursor, cursor + count - 1, file_id(entry['file'])))
                cursor += count
            if cursor != source['lines'] + 1:
                raise ValueError('incomplete merged source provenance')
        else:
            spans = [(1, source['lines'], file_id(row['file']))]

        raw_digest, seen, span = hashlib.sha256(), bytearray(unique), 0
        raw_bytes = raw_lf = 0
        for line, (ordinal,) in enumerate(struct.iter_unpack('<Q', mapping), 1):
            if not 1 <= ordinal <= unique:
                raise ValueError('invalid line-map ordinal')
            seen[ordinal - 1] = 1
            original = hashes[(ordinal - 1) * 41:ordinal * 41]
            if line == source['lines'] and not raw['terminated']:
                original = original[:-1]
            raw_digest.update(original)
            raw_bytes += len(original)
            raw_lf += original.endswith(b'\n')
            while line > spans[span][1]:
                span += 1
            first, _, fid = spans[span]
            packed.append(PACKED.pack(digests[ordinal - 1], fid, line - first + 1))
        if (not all(seen) or raw_bytes != raw['bytes'] or raw_lf != raw['newlines']
                or raw_digest.hexdigest().upper() != raw['sha256'].upper()):
            raise ValueError('original-order hash reconstruction failed: ' + row['file'])
    packed.sort()
    if any(a == b for a, b in zip(packed, packed[1:])):
        raise ValueError('duplicate hash/file/line provenance')
    return catalog, packed


def build(root, output, rows, plan, memory, reserve):
    if plan['memoryBudgetBytes'] > memory:
        raise RuntimeError('memory budget insufficient; inputs unchanged')
    if shutil.disk_usage(output.parent).free < reserve + plan['estimatedMaximumIndexBytes']:
        raise RuntimeError('disk reserve insufficient; inputs unchanged')
    staging = output.with_name(output.name + '.verifying')
    receipt = output.with_name(output.name + '.receipt.json')
    if any(p.exists() for p in (output, staging, receipt, Path(str(staging) + '.partial'))):
        raise FileExistsError('output or verification artifacts already exist; inspect before resuming')
    if not rows:
        raise ValueError('no finalized files selected')
    cleanup_path = root / 'cleanup.json'
    cleanup = json.loads(cleanup_path.read_text()) if cleanup_path.exists() else {}
    files, packed = load_records(root, rows, cleanup)
    records = ((*PACKED.unpack(record), 1) for record in packed)
    report = build_index(staging, files, records, reserve=reserve)
    if report['occurrences'] != plan['originalLines']:
        raise ValueError('saved occurrence count mismatch')
    index = Index(staging)
    try:
        if index.files != files:
            raise ValueError('saved catalog mismatch')
        position = 0
        for digest, fid, first, count in index.records():
            for line in range(first, first + count):
                if position >= len(packed) or PACKED.pack(digest, fid, line) != packed[position]:
                    raise ValueError('saved provenance mismatch')
                position += 1
        if position != len(packed):
            raise ValueError('saved original-line count mismatch')
    finally:
        index.close()
    report.update(plan)
    report.update({'state': 'verified', 'savedProvenanceVerified': True,
                   'originalOrderHashChecksumsVerified': True, 'inputsDeleted': False,
                   'sources': rows})
    with receipt.open('x') as stream:
        json.dump(report, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(staging, output)
    staging.unlink()
    directory = os.open(output.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--max-lines', type=int, default=200_000_000)
    parser.add_argument('--memory-bytes', type=int, default=64_000_000_000)
    parser.add_argument('--reserve-bytes', type=int, default=150_000_000_000)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--build', action='store_true')
    mode.add_argument('--verify-inputs', action='store_true', help='verify in RAM without writing an index')
    args = parser.parse_args()
    if min(args.max_lines, args.memory_bytes) <= 0 or args.reserve_bytes < 0:
        parser.error('invalid resource limits')
    # Coordinate with the old inventory driver; never mutate its conversion state.
    with (args.inventory / 'run.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rows, plan = selection(args.inventory, args.max_lines)
        if args.build:
            build(args.inventory, args.output, rows, plan, args.memory_bytes, args.reserve_bytes)
        elif args.verify_inputs:
            if plan['memoryBudgetBytes'] > args.memory_bytes:
                raise RuntimeError('memory budget insufficient; inputs unchanged')
            cleanup_path = args.inventory / 'cleanup.json'
            cleanup = json.loads(cleanup_path.read_text()) if cleanup_path.exists() else {}
            files, packed = load_records(args.inventory, rows, cleanup)
            if len(packed) != plan['originalLines']:
                raise ValueError('original-line count mismatch')
        state = 'verified' if args.build else 'inputs_verified' if args.verify_inputs else 'planned'
        print(json.dumps({**plan, 'state': state}, indent=2))
