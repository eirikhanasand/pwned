"""Retire only hash/map files superseded by a verified, durable compact overlay.

Default is a read-only plan. Run --retire only after checking live lookup. The
registry records exact source metadata and index checksum before each unlink;
old conversion receipts remain immutable audit history. No plaintext is touched.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

from compact_index import Index
from finalize_inventory import save_receipt, sync_directory


def exact(root, name):
    relative = Path(name)
    path = root / relative
    if (relative.is_absolute() or '..' in relative.parts or not relative.parts
            or relative.parts[0] != 'files' or path.is_symlink()
            or not path.resolve().is_relative_to(root.resolve())):
        raise ValueError('unsafe legacy hash/map path')
    return path


def run(root, index_path, retire=False):
    receipt = json.loads(Path(str(index_path) + '.receipt.json').read_text())
    native = (receipt.get('originalSourceChecksumsVerified') is True
              and receipt.get('preDeduplicationCountsVerified') is True)
    if (receipt.get('state') != 'verified' or not receipt.get('savedProvenanceVerified')
            or not (receipt.get('originalOrderHashChecksumsVerified') or native)):
        raise ValueError('requires verified compact-overlay receipt')
    if not stat.S_ISREG(index_path.stat(follow_symlinks=False).st_mode):
        raise ValueError('index must be a regular disk file')
    with index_path.open('rb') as stream:
        if (os.fstat(stream.fileno()).st_size != receipt['bytes']
                or hashlib.file_digest(stream, 'sha256').hexdigest() != receipt['sha256']):
            raise ValueError('durable index checksum differs')
    index = Index(index_path)
    try:
        if index.unique != receipt['uniqueHashes']:
            raise ValueError('saved index count differs')
        catalog = set(index.files)
    finally:
        index.close()
    rows = json.loads((root / 'converted.json').read_text())
    rows = {r['file']: r for r in rows}
    # A separate lock coordinates retirement only. The remaining-source runner
    # can hold run.lock while reading immutable metadata; it never opens these
    # completed inputs. The old driver refuses the compacted registry entirely.
    lock = (root / 'compact-retirement.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    registry_path = root / 'compacted.json'
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {}
    planned = removed = matched = 0
    for saved in receipt['sources']:
        row = rows.get(saved['file'])
        if native:
            # Newly converted originals have no old text hashes to retire.
            if row is None:
                continue
            if (row.get('deduplicated') or row['source'] != saved['source']
                    or row['file'] not in catalog
                    or any(row['source'][k] != row['output'][k] for k in ('lines', 'newlines', 'terminated'))
                    or not 0 <= saved['uniqueHashes'] <= saved['source']['lines']):
                raise ValueError('native replacement does not verify this legacy raw source')
            paths = (('outputPath', 'output'),)
        else:
            if row != saved or not row.get('deduplicated'):
                raise ValueError('legacy source receipt changed')
            paths = (('outputPath', 'output'), ('lineMapPath', 'lineMap'))
        matched += 1
        entry = {'index': index_path.name, 'indexSha256': receipt['sha256'], 'source': row}
        prior = registry.get(row['file'])
        if prior and any(prior.get(k) != v for k, v in entry.items()):
            raise ValueError('retirement registry changed')
        for path_key, metadata_key in paths:
            path, expected = exact(root, row[path_key]), row[metadata_key]
            if not path.exists():
                if not prior:
                    raise ValueError('unrecorded missing hash/map')
                continue
            with path.open('rb') as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_size != expected['bytes']
                        or hashlib.file_digest(stream, 'sha256').hexdigest().upper() != expected['sha256'].upper()):
                    raise ValueError('legacy hash/map checksum changed')
            planned += expected['bytes']
            if retire:
                registry[row['file']] = {**entry, 'state': 'retiring'}
                save_receipt(registry_path, registry)
                after = path.stat(follow_symlinks=False)
                if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise ValueError('legacy hash/map changed before unlink')
                path.unlink()
                sync_directory(path.parent)
                removed += expected['bytes']
                prior = registry[row['file']]
        if retire:
            registry[row['file']] = {**entry, 'state': 'retired'}
            save_receipt(registry_path, registry)
    return {'state': 'retired' if retire else 'planned', 'sourceFiles': matched,
            'plannedBytes': planned, 'removedBytes': removed, 'originalsTouched': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('index', type=Path)
    parser.add_argument('--retire', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run(args.inventory, args.index, args.retire)))
