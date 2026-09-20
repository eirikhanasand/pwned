#!/usr/bin/env python3
"""Resumable, smallest-first SHA-1 inventory conversion; originals stay read-only."""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from finalize_inventory import finalize


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def snapshot(path):
    s = path.stat(follow_symlinks=False)
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def identical(first, second):
    with first.open('rb') as a, second.open('rb') as b:
        while True:
            left = a.read(8 * 1024 * 1024)
            right = b.read(8 * 1024 * 1024)
            if left != right:
                return False
            if not left:
                return True


def run(args):
    source, destination = args.source.resolve(), args.destination.resolve()
    if destination == source or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError('source and destination must be separate, non-overlapping directories')
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = (destination / 'run.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    plan_path = destination / 'inventory.json'
    if plan_path.exists():
        plan = json.loads(plan_path.read_text())
        if plan['source'] != str(source):
            raise ValueError('existing inventory belongs to a different source')
    else:
        files, excluded = [], []
        def walk_error(error):
            raise error
        for base, dirs, names in os.walk(source, followlinks=False, onerror=walk_error):
            for name in list(dirs):
                child = Path(base) / name
                if name.startswith('.') or child.is_symlink():
                    excluded.append({'file': str(child.relative_to(source)), 'reason': 'metadata directory or symlink'})
                    dirs.remove(name)
            for name in names:
                child = Path(base) / name
                relative = str(child.relative_to(source))
                if child.is_symlink() or not child.is_file() or child.suffix != '.txt' or name == 'lookup.txt':
                    excluded.append({'file': relative, 'reason': 'archive, metadata, non-text file, or symlink'})
                    continue
                info = snapshot(child)
                files.append({'file': relative, 'bytes': info[2], 'snapshot': info})
        files.sort(key=lambda entry: (entry['bytes'], entry['file']))
        plan = {'version': 1, 'createdAt': stamp(), 'source': str(source), 'files': files, 'excluded': excluded}
        atomic_json(plan_path, plan)

    records = {}
    journal_path = destination / 'journal.jsonl'
    if journal_path.exists():
        with journal_path.open() as stream:
            for line in stream:
                # A torn journal is an explicit error, never silent success.
                value = json.loads(line)
                records[value['file']] = value
    groups = {}
    for item in records.values():
        if item.get('source'):
            groups.setdefault((item['source']['bytes'], item['source']['sha256']), []).append(item['file'])
    current = None
    last_report = 0
    pause_requested = False

    def pause(_signal, _frame):
        nonlocal pause_requested
        pause_requested = True

    signal.signal(signal.SIGINT, pause)
    signal.signal(signal.SIGTERM, pause)

    def report(state, force=False):
        nonlocal last_report
        if not force and time.monotonic() - last_report < 30:
            return
        last_report = time.monotonic()
        converted, remaining = [], []
        for item in plan['files']:
            value = records.get(item['file'], {'file': item['file'], 'bytes': item['bytes'], 'status': 'pending'})
            (converted if value['status'] == 'converted' else remaining).append(value)
        duplicates = [{'files': members, 'bytesEach': key[0], 'sha256': key[1]}
                      for key, members in groups.items() if len(members) > 1]
        data = {
            'updatedAt': stamp(), 'state': state, 'currentFile': current,
            'source': str(source), 'hashRoot': str(destination / 'files'),
            'memoryLimitBytes': args.memory_limit, 'diskReserveBytes': args.reserve,
            'originalsModified': bool(plan.get('normalization')) or any(v.get('originalDeleted') for v in converted),
            'sourceInventoryNormalized': bool(plan.get('normalization')), 'scannedFiles': len(records),
            'totalFiles': len(plan['files']), 'convertedFiles': len(converted),
            'remainingFiles': len(remaining), 'duplicateGroups': len(duplicates),
            'inputLinesConverted': sum(v['source']['lines'] for v in converted),
            'outputLinesVerified': sum(v.get('rawOutput', v['output'])['lines'] for v in converted),
            'storedHashLines': sum(v['output']['lines'] for v in converted),
            'deduplicatedFiles': sum(bool(v.get('deduplicated')) for v in converted),
            'duplicateHashesRemoved': sum(v.get('duplicateHashesRemoved', 0) for v in converted),
            'originalFilesDeleted': sum(bool(v.get('originalDeleted')) for v in converted),
            'finalizationBlockedFiles': sum(bool(v.get('finalizationBlocked')) for v in converted),
            'freeDiskBytes': shutil.disk_usage(destination).free,
            'duplicatesAuditComplete': len(records) == len(plan['files']) and all('source' in r for r in records.values()),
        }
        atomic_json(destination / 'summary.json', data)
        atomic_json(destination / 'converted.json', converted)
        atomic_json(destination / 'remaining.json', remaining)
        atomic_json(destination / 'duplicates.json', duplicates)
        print(json.dumps(data), flush=True)

    def worker(*parameters):
        process = subprocess.Popen([str(args.worker), *map(str, parameters)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            try:
                stdout, stderr = process.communicate(timeout=20)
                break
            except subprocess.TimeoutExpired:
                report('running', True)
        if process.returncode:
            raise RuntimeError(stderr.strip() or 'worker failed')
        return json.loads(stdout)

    try:
        with journal_path.open('a') as journal:
            def record_result(result):
                journal.write(json.dumps(result) + '\n')
                journal.flush()
                os.fsync(journal.fileno())
                records[result['file']] = result

            def finish(item, result):
                if not args.deduplicate:
                    return
                try:
                    finalized = finalize(item, result, source, destination, worker, args.reserve,
                                         args.memory_limit * 4 // 5, args.delete_verified_originals)
                    finalized.pop('finalizationBlocked', None)
                    record_result(finalized)
                except RuntimeError as error:
                    if not any(reason in str(error) for reason in ('disk reserve reached', 'memory budget reached')):
                        raise
                    record_result({**result, 'finalizationBlocked': str(error)})

            for item in plan['files']:
                if pause_requested:
                    current = None
                    report('paused', True)
                    return
                current = item['file']
                original = source / current
                output = destination / 'files' / (current + '.sha1')
                prior = records.get(current)
                report('running')
                receipt = destination / 'finalization' / (current + '.json')
                if prior and prior['status'] == 'converted' and (args.deduplicate or receipt.exists()):
                    if not args.deduplicate:
                        raise RuntimeError('resume finalized inventory with --deduplicate')
                    finish(item, prior)
                    report('running')
                    continue
                if snapshot(original) != item['snapshot']:
                    raise RuntimeError('source inventory changed: ' + current)
                if prior and prior['status'] == 'converted':
                    if not output.is_file() or worker('scan', output) != prior['output']:
                        raise RuntimeError('previous output failed verification: ' + current)
                    continue
                scanned = prior.get('source') if prior else None
                scanned = scanned or worker('scan', original)
                if snapshot(original) != item['snapshot']:
                    raise RuntimeError('source changed during scan: ' + current)
                key = (scanned['bytes'], scanned['sha256'])
                members = groups.setdefault(key, [])
                if current not in members:
                    if members and (source / members[0]).exists() and not identical(original, source / members[0]):
                        raise RuntimeError('checksum collision or changed duplicate: ' + current)
                    members.append(current)
                expected = scanned['lines'] * 41 - (1 if scanned['lines'] and not scanned['terminated'] else 0)
                result = {'file': current, 'status': 'pending', 'source': scanned, 'expectedOutputBytes': expected}
                canonical = next((records[name] for name in members if name != current and records.get(name, {}).get('status') == 'converted' and not records[name].get('deduplicated')), None)
                output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                partial = output.with_suffix(output.suffix + '.partial')
                if output.exists():
                    raise RuntimeError('unrecorded output exists; inspect before resuming: ' + current)
                # Only remove the exact unfinished output owned by this run.
                if partial.exists():
                    partial.unlink()
                if canonical:
                    os.link(destination / canonical['outputPath'], partial)
                    verified = worker('scan', partial)
                    if verified != canonical['output']:
                        raise RuntimeError('duplicate output verification failed: ' + current)
                    result.update(output=verified, duplicateOf=canonical['file'])
                elif shutil.disk_usage(destination).free < args.reserve + expected:
                    result.update(status='blocked_space', reason='insufficient space above reserved headroom')
                else:
                    try:
                        converted = worker('convert', original, partial, args.reserve, args.threads)
                        if converted['source'] != scanned:
                            raise RuntimeError('source changed between scan and conversion')
                        result['output'] = converted['output']
                    except RuntimeError as error:
                        if partial.exists():
                            partial.unlink()
                        if 'disk reserve reached' not in str(error):
                            raise
                        result.update(status='blocked_space', reason=str(error))
                if 'output' in result:
                    if snapshot(original) != item['snapshot'] or result['output']['lines'] != scanned['lines'] or result['output']['newlines'] != scanned['newlines']:
                        raise RuntimeError('source or line count mismatch: ' + current)
                    os.chmod(partial, 0o400)
                    partial.replace(output)
                    directory = os.open(output.parent, os.O_DIRECTORY)
                    os.fsync(directory)
                    os.close(directory)
                    result.update(status='converted', outputPath=str(output.relative_to(destination)), verifiedAt=stamp())
                record_result(result)
                if result['status'] == 'converted':
                    finish(item, result)
                report('running')
            current = None
            state = 'blocked_resources' if any(v.get('finalizationBlocked') for v in records.values()) else ('complete' if all(v['status'] == 'converted' for v in records.values()) else 'blocked_space')
            report(state, True)
    except BaseException:
        report('failed', True)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--reserve', type=int, default=150_000_000_000)
    parser.add_argument('--memory-limit', type=int, default=500_000_000_000)
    parser.add_argument('--threads', type=int, default=16)
    parser.add_argument('--deduplicate', action='store_true')
    parser.add_argument('--delete-verified-originals', action='store_true')
    options = parser.parse_args()
    if options.delete_verified_originals and not options.deduplicate:
        parser.error('source removal requires --deduplicate')
    # Legacy lookup manifests still depend on source files. Migrating/retiring that
    # consumer must precede deletion; never silently break it during conversion.
    if options.delete_verified_originals and any(options.source.rglob('lookup.txt')):
        parser.error('legacy lookup manifests remain; migrate or retire that consumer before source removal')
    if options.reserve < 0 or not 1 <= options.threads <= 96:
        parser.error('invalid disk reserve or thread count')
    # The launcher owns enforcement; the report records the verified cgroup cap.
    cgroup = Path('/sys/fs/cgroup/memory.max')
    if cgroup.exists():
        actual = cgroup.read_text().strip()
        if actual == 'max' or int(actual) > options.memory_limit:
            parser.error('run inside a memory-limited cgroup at or below the requested limit')
        options.memory_limit = int(actual)
    run(options)
