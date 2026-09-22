"""Native RAM conversion of remaining originals with verified, exact retirement.

The master and completed overlays are immutable. Only explicit inventory paths
can be removed. RAM-only retirement is opt-in and occurs ONLY after the entire
saved RAM index passes native full-block/provenance verification. The container
must retain its tmpfs on errors until the durable publisher can finish.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

from compact_index import Index
from finalize_inventory import save_receipt, sync_directory


def load_publisher():
    spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-compact-overlay.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_path(root, name):
    relative = Path(name)
    path = root / relative
    if (relative.is_absolute() or not relative.parts or '..' in relative.parts
            or any(c in str(path) for c in '\t\r\n') or path.is_symlink()
            or not path.resolve().is_relative_to(root.resolve())):
        raise ValueError('unsafe inventory path')
    return path


def snapshot(path):
    s = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode):
        raise ValueError('expected regular source')
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def scan(scanner, path):
    return json.loads(subprocess.check_output([str(scanner), 'scan', str(path)]))


def verify_source(root, entry, scanner):
    path = safe_path(root, entry['file'])
    if snapshot(path) != entry['snapshot']:
        raise ValueError('source snapshot changed: ' + entry['file'])
    if scan(scanner, path) != entry['source'] or snapshot(path) != entry['snapshot']:
        raise ValueError('source checksum/count changed: ' + entry['file'])
    return path


def retire_source(root, entry, scanner, journal, index_sha, ram_only):
    """A durable deletion intent permits recovery across unlink/journal crashes."""
    name = entry['file']
    prior = journal['files'].get(name)
    if prior and (prior['source'] != entry['source'] or prior['snapshot'] != entry['snapshot']
                  or prior['indexSha256'] != index_sha):
        raise ValueError('retirement intent changed')
    path = safe_path(root, name)
    if not path.exists():
        if not prior:
            raise ValueError('source disappeared without retirement intent')
    else:
        verify_source(root, entry, scanner)
        journal['files'][name] = {**entry, 'indexSha256': index_sha,
                                  'ramOnlyAtDeletion': ram_only, 'state': 'deleting'}
        save_receipt(journal['path'], {k: v for k, v in journal.items() if k != 'path'})
        if snapshot(path) != entry['snapshot']:
            raise ValueError('source changed before unlink')
        path.unlink()
        sync_directory(path.parent)
    journal['files'][name]['state'] = 'deleted'
    save_receipt(journal['path'], {k: v for k, v in journal.items() if k != 'path'})


def run(args):
    source, output, work = args.source.resolve(), args.output.resolve(), args.work.resolve()
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for a, b in ((source, output), (source, work), (output, work))):
        raise ValueError('source, durable output and RAM work must be separate')
    output.mkdir(exist_ok=True)
    work.mkdir(exist_ok=True)
    if args.release_sources_from_ram:
        # statfs magic of a size-limited tmpfs; do not authorize volatile retirement
        # for a guessed path on an ordinary disk or a swap-backed mount.
        fs = subprocess.check_output(['stat', '-f', '-c', '%t', str(work)], text=True).strip()
        if fs != '1021994':
            raise ValueError('RAM-source retirement requires explicit tmpfs work directory')
        swap = Path('/sys/fs/cgroup/memory.swap.max')
        if not swap.exists() or swap.read_text().strip() != '0':
            raise ValueError('RAM-source retirement requires a no-swap container')
    lock = (args.inventory / 'run.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    run_lock = (output / 'remaining.run.lock').open('a')
    fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    status_path = output / 'remaining.status.json'

    def status(state, **extra):
        data = {'state': state, 'updatedAt': time.time(), **extra}
        save_receipt(status_path, data)
        print(json.dumps(data), flush=True)

    covered = set()
    for path in args.covered_index:
        index = Index(path)
        try:
            if covered.intersection(index.files):
                raise ValueError('overlapping completed indexes')
            covered.update(index.files)
        finally:
            index.close()
    # Aggregate names (small.txt) may differ from restored original catalogs.
    for path in args.covered_receipt:
        receipt = json.loads(path.read_text())
        if receipt.get('state') != 'verified' or not receipt.get('savedProvenanceVerified'):
            raise ValueError('unverified completed overlay receipt')
        covered.update(row['file'] for row in receipt['sources'])
    inventory = json.loads((args.inventory / 'inventory.json').read_text())
    items = sorted((r for r in inventory['files'] if r['file'] not in covered),
                   key=lambda r: (r['bytes'], r['file']))
    if len({r['file'] for r in items}) != len(items) or not items:
        raise ValueError('invalid remaining inventory')
    plan_path = output / 'remaining.plan.json'
    expected_names = [r['file'] for r in items]
    if plan_path.exists():
        plan = json.loads(plan_path.read_text())
        if plan['files'] != expected_names or plan['snapshots'] != [r['snapshot'] for r in items]:
            raise ValueError('remaining inventory changed')
    else:
        plan = {'files': expected_names, 'snapshots': [r['snapshot'] for r in items], 'sources': []}
        save_receipt(plan_path, plan)
    for item in items[len(plan['sources']):]:
        path = safe_path(source, item['file'])
        if snapshot(path) != item['snapshot']:
            raise ValueError('original inventory snapshot changed: ' + item['file'])
        status('profiling', file=item['file'], scannedFiles=len(plan['sources']), totalFiles=len(items))
        info = scan(args.scanner, path)
        if snapshot(path) != item['snapshot'] or info['bytes'] != item['bytes']:
            raise ValueError('source changed during profile')
        plan['sources'].append({'file': item['file'], 'source': info, 'snapshot': item['snapshot']})
        save_receipt(plan_path, plan)
    rows = plan['sources']
    lines = sum(r['source']['lines'] for r in rows)
    # Packed records, permutation bitmap, native buffers and conservative RAM output.
    estimate = lines * 100 + 8 * 1024**3
    if estimate > args.memory_bytes:
        raise ValueError('planned records and RAM output exceed memory budget; sources untouched')
    ram = work / 'remaining.pwnidx'
    target = output / 'remaining.pwnidx'
    receipt_path = Path(str(ram) + '.receipt.json')
    manifest = work / 'remaining.manifest.tsv'
    if not ram.exists():
        for entry in rows:
            if snapshot(safe_path(source, entry['file'])) != entry['snapshot']:
                raise ValueError('source changed after profile')
        data = ''.join('\t'.join([str(safe_path(source, r['file'])), r['file'],
                       str(r['source']['lines']), str(r['source']['newlines']),
                       str(r['source']['bytes']), r['source']['sha256'].lower()]) + '\n' for r in rows).encode()
        with manifest.open('xb') as stream:
            stream.write(data)
        if shutil.disk_usage(work).free < lines * 65 + 16 * 1024**2:
            raise ValueError('RAM output filesystem too small; sources untouched')
        status('building_in_memory', totalFiles=len(rows), originalLines=lines, memoryBudgetBytes=estimate)
        with (work / 'native.log').open('x') as log:
            subprocess.run([str(args.builder), str(manifest), str(ram), 'batch', str(lines),
                            str(sum(r['source']['newlines'] for r in rows)), str(len(data)),
                            hashlib.sha256(data).hexdigest(), str(args.memory_bytes), '0', str(args.threads)],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    if not receipt_path.exists():
        native = json.loads(Path(str(ram) + '.status.json').read_text())
        with (work / 'native.log').open() as stream:
            for last in stream:
                pass
        counts = json.loads(last)
        if (native.get('state') != 'complete' or not native.get('savedProvenanceVerified')
                or not native.get('preDeduplicationCountsVerified') or native['verifiedLines'] != lines
                or counts.get('state') != 'batch_complete' or len(counts['fileUniqueHashes']) != len(rows)):
            raise ValueError('native full verification incomplete; sources retained')
        for row, unique in zip(rows, counts['fileUniqueHashes']):
            row['uniqueHashes'] = unique
        receipt = {'state': 'verified', 'bytes': native['writtenBytes'], 'sha256': native['indexSha256'],
                   'uniqueHashes': native['uniqueHashes'], 'occurrences': lines, 'originalLines': lines,
                   'selectedFiles': len(rows), 'savedProvenanceVerified': True,
                   'preDeduplicationCountsVerified': True, 'originalSourceChecksumsVerified': True,
                   'inputsDeleted': False, 'sources': rows}
        save_receipt(receipt_path, receipt)
    receipt = json.loads(receipt_path.read_text())
    if receipt['originalLines'] != lines or [r['file'] for r in receipt['sources']] != expected_names:
        raise ValueError('RAM receipt differs from plan')
    # Independently validate the full RAM checksum before authorizing any deletion.
    with ram.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != receipt['sha256']:
            raise ValueError('RAM index checksum differs; sources retained')
    index = Index(ram)
    try:
        if index.files != expected_names or index.unique != receipt['uniqueHashes']:
            raise ValueError('RAM catalog/count differs')
    finally:
        index.close()
    journal_path = output / 'remaining.retirement.json'
    journal = json.loads(journal_path.read_text()) if journal_path.exists() else {'files': {}}
    journal['path'] = journal_path
    status('ram_verified', files=len(rows), originalLines=lines, indexBytes=receipt['bytes'])
    # Only exact checked originals may be released to make room, smallest first.
    if args.release_sources_from_ram and not target.exists():
        for entry in rows:
            if shutil.disk_usage(output).free >= args.reserve_bytes + receipt['bytes'] + 4 * 1024**2:
                break
            retire_source(source, entry, args.scanner, journal, receipt['sha256'], True)
            status('releasing_verified_sources', deletedFiles=len(journal['files']),
                   totalFiles=len(rows), ramOnly=True)

    def wait(state, saved, total):
        status(state, savedBytes=saved, totalBytes=total, ramRetained=True)
        time.sleep(30)

    result = load_publisher().publish(ram, target, args.reserve_bytes, wait, owner=args.owner)
    status('published', **{k: v for k, v in result.items() if k != 'state'})
    for entry in rows:
        retire_source(source, entry, args.scanner, journal, receipt['sha256'], False)
    report = {'state': 'converted', 'index': target.name, 'sha256': receipt['sha256'],
              'files': receipt['sources'], 'remaining': [], 'originalLines': lines,
              'uniqueHashes': receipt['uniqueHashes'], 'indexBytes': receipt['bytes'],
              'deletedOriginalFiles': len(journal['files']), 'liveConfigured': False}
    save_receipt(output / 'remaining.report.json', report)
    status('complete', convertedFiles=len(rows), originalLines=lines,
           uniqueHashes=receipt['uniqueHashes'], indexBytes=receipt['bytes'],
           deletedOriginalFiles=len(journal['files']), liveConfigured=False)
    # Keep RAM until the serving path has also been checked; the owning container
    # remains alive, but the native packed sort array was already returned.


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('source', 'inventory', 'output', 'work', 'builder', 'scanner'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--covered-index', action='append', type=Path, default=[])
    parser.add_argument('--covered-receipt', action='append', type=Path, default=[])
    parser.add_argument('--memory-bytes', type=int, default=480_000_000_000)
    parser.add_argument('--reserve-bytes', type=int, default=20_000_000_000)
    parser.add_argument('--threads', type=int, default=16)
    parser.add_argument('--owner', type=int, default=1000)
    parser.add_argument('--release-sources-from-ram', action='store_true')
    args = parser.parse_args()
    if args.memory_bytes <= 0 or args.reserve_bytes < 0 or not 1 <= args.threads <= 64:
        parser.error('invalid limits')
    try:
        run(args)
    except Exception as error:
        save_receipt(args.output / 'remaining.status.json', {
            'state': 'failed', 'updatedAt': time.time(), 'error': str(error),
            'keepRamContainerAlive': True})
        raise
