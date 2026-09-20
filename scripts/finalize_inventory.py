"""Crash-resumable publication of unique hashes and original-line mappings."""
import json
import os
from pathlib import Path


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_receipt(path, value):
    temporary = path.with_suffix('.json.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    sync_directory(path.parent)


def finalize(item, record, source, destination, worker, reserve, memory, delete_original=False):
    name = item['file']
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('unsafe inventory path')
    original = source / relative
    output = destination / 'files' / (name + '.sha1')
    mapping = destination / 'files' / (name + '.sha1.lines')
    receipt_path = destination / 'finalization' / (name + '.json')
    staged_output = output.with_name(output.name + '.dedup.partial')
    staged_mapping = mapping.with_name(mapping.name + '.partial')

    def verify_original():
        s = original.stat(follow_symlinks=False)
        if [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns] != item['snapshot']:
            raise RuntimeError('source changed before removal: ' + name)
        if worker('scan', original) != record['source']:
            raise RuntimeError('source checksum changed before removal: ' + name)

    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        if receipt['file'] != name or receipt['source'] != record['source'] or receipt['snapshot'] != item['snapshot']:
            raise RuntimeError('finalization receipt does not match source: ' + name)
        if receipt['rawOutput'] != record.get('rawOutput', record['output']):
            raise RuntimeError('pre-deduplication evidence changed: ' + name)
        if original.exists():
            verify_original()
    else:
        if mapping.exists():
            raise RuntimeError('unrecorded line map exists; inspect before finalizing: ' + name)
        verify_original()
        raw = record['output']
        if record.get('deduplicated') or raw['lines'] != record['source']['lines'] or raw['newlines'] != record['source']['newlines']:
            raise RuntimeError('pre-deduplication line counts do not match: ' + name)
        if worker('scan', output) != raw:
            raise RuntimeError('full hash file failed verification: ' + name)
        # These exact unpublished paths are owned by this finalization transaction.
        for path in (staged_output, staged_mapping):
            if path.exists():
                path.unlink()
        result = worker('deduplicate', output, staged_output, staged_mapping, reserve, memory)
        if result['input'] != raw or result['output']['lines'] > raw['lines'] or result['lineMap']['bytes'] != raw['lines'] * 8:
            raise RuntimeError('deduplication verification failed: ' + name)
        receipt = {'file': name, 'snapshot': item['snapshot'], 'source': record['source'],
                   'rawOutput': raw, 'output': result['output'], 'lineMap': result['lineMap'],
                   'deleteAuthorized': delete_original}
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        sync_directory(output.parent)
        save_receipt(receipt_path, receipt)

    # A durable receipt precedes either replacement. On resumption verify whichever
    # copy exists, allowing a crash between the two atomic publications.
    for staged, final, expected in ((staged_output, output, receipt['output']), (staged_mapping, mapping, receipt['lineMap'])):
        candidate = staged if staged.exists() else final
        if worker('scan', candidate) != expected:
            raise RuntimeError('published hash/map failed verification: ' + name)
        if candidate == staged:
            os.chmod(staged, 0o400)
            staged.replace(final)
            sync_directory(final.parent)
    if delete_original and original.exists():
        verify_original()
        if not receipt['deleteAuthorized']:
            receipt['deleteAuthorized'] = True
            save_receipt(receipt_path, receipt)
        # Check once more after the source scan, immediately before the exact unlink.
        s = original.stat(follow_symlinks=False)
        if [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns] != item['snapshot']:
            raise RuntimeError('source changed during removal verification: ' + name)
        original.unlink()
        sync_directory(original.parent)
    deleted = not original.exists()
    if deleted and not receipt['deleteAuthorized']:
        raise RuntimeError('source disappeared without deletion authorization: ' + name)
    return {**record, 'output': receipt['output'], 'rawOutput': receipt['rawOutput'],
            'lineMap': receipt['lineMap'], 'lineMapPath': str(mapping.relative_to(destination)),
            'deduplicated': True, 'duplicateHashesRemoved': receipt['rawOutput']['lines'] - receipt['output']['lines'],
            'originalDeleted': deleted}
