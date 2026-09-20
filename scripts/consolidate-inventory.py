#!/usr/bin/env python3
"""Remove username-only lists and consolidate short inventory lists, recoverably."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HASH_FIXTURES = {'haval160,3.txt', 'haval160,4.txt', 'ripemd160.txt', 'tiger160,3.txt', 'tiger160,4.txt', 'tiger192,3.txt', 'pbkdf2-sha224.txt', 'pbkdf2-sha256.txt'}


def snapshot(path):
    s = path.stat(follow_symlinks=False)
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def save(path, data):
    temporary = path.with_name(path.name + '.new')
    with temporary.open('xb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)


def json_save(path, data):
    save(path, (json.dumps(data, indent=2) + '\n').encode())


def consolidate(source, report, backup, worker, apply=False, under_lines=None):
    if under_lines is not None and under_lines < 1:
        raise ValueError('line threshold must be positive')
    threshold = under_lines if under_lines is not None else 2
    source, report, backup = source.resolve(), report.resolve(), backup.resolve()
    if backup == source or backup.is_relative_to(source) or backup.is_relative_to(report):
        raise ValueError('backup must be outside the active inventory and conversion directory')
    lock = (report / 'run.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    plan = json.loads((report / 'inventory.json').read_text())
    records = {}
    for line in (report / 'journal.jsonl').read_text().splitlines():
        row = json.loads(line)
        records[row['file']] = row
    previous = plan.get('normalization', {})
    existing = (source / 'small.txt').exists()
    merged = b''
    if existing:
        if under_lines is None or not previous:
            raise ValueError('small.txt already exists; explicit threshold and prior provenance required')
        merged = (source / 'small.txt').read_bytes()
        if hashlib.sha256(merged).hexdigest().upper() != previous['smallSha256'] or merged.count(b'\n') != previous['smallLines'] or (merged and not merged.endswith(b'\n')):
            raise ValueError('existing small.txt does not match the recorded consolidation')
    elif previous or any(row['file'] == 'small.txt' for row in plan['files']):
        raise ValueError('recorded small.txt is missing')
    usernames, short_files, mixed = [], [], []
    combined_bytes = len(merged)
    for row in plan['files']:
        name = row['file']
        path = source / name
        if snapshot(path) != row['snapshot']:
            raise ValueError('source changed: ' + name)
        if name == 'small.txt':
            continue
        basename = path.name.lower()
        if re.search(r'users?|usernames?|userlist', basename) and 'password' not in basename:
            usernames.append(name)
            continue
        if under_lines is None and re.search(r'user', basename) and 'password' in basename:
            mixed.append(name)
            continue
        if under_lines is None and path.name in HASH_FIXTURES:
            continue
        old = records.get(name)
        if old:
            count = old['source']['lines']
        else:
            with path.open('rb') as stream:
                prefix = stream.read(65536)
            # A bounded prefix proves most large lists cannot qualify.
            if prefix.count(b'\n') >= threshold:
                continue
            count = json.loads(subprocess.check_output([str(worker), 'scan', str(path)]))['lines']
        if count < threshold and (under_lines is not None or count == 1):
            if row['bytes'] > 64 * 1024 * 1024:
                raise ValueError('unusually large short list needs review: ' + name)
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest().upper()
            if old and digest != old['source']['sha256']:
                raise ValueError('short-list checksum changed: ' + name)
            values = raw.split(b'\n') if raw else []
            if raw.endswith(b'\n'):
                values.pop()
            if len(values) != count:
                raise ValueError('short-list line count changed: ' + name)
            normalized = b''.join(value.removesuffix(b'\r') + b'\n' for value in values)
            combined_bytes += len(normalized)
            if combined_bytes > 256 * 1024 * 1024:
                raise ValueError('combined short lists exceed the in-memory cleanup budget')
            short_files.append((name, normalized, digest, count))
    short_files.sort(key=lambda row: row[0])
    if not short_files:
        raise ValueError('no qualifying short files found; inventory unchanged')
    mapping = list(previous.get('mergedFiles', []))
    line_count = merged.count(b'\n')
    for name, value, digest, count in short_files:
        mapping.append({'file': name, 'sourceSha256': digest, 'originalLine': 1 if count else None,
                        'smallLine': line_count + 1 if count else None, 'lineCount': count})
        line_count += count
    merged += b''.join(row[1] for row in short_files)
    actions = {
        'usernameFilesRemoved': sorted(set(previous.get('usernameFilesRemoved', [])) | set(usernames)),
        'mergedFiles': mapping,
        'mixedListsPreserved': mixed,
        'hashFixturesPreserved': sorted(HASH_FIXTURES & {Path(row['file']).name for row in plan['files']}) if under_lines is None else [],
        'smallFile': 'small.txt', 'smallLines': line_count,
        'duplicatesPreserved': True, 'backupDirectory': str(backup),
        'previousBackupDirectories': previous.get('previousBackupDirectories', []) + ([previous['backupDirectory']] if previous else []),
        'underLines': threshold,
        'changesThisRun': {'mergedFiles': [row[0] for row in short_files], 'addedLines': sum(row[3] for row in short_files), 'usernameFilesRemoved': sorted(usernames)},
        'smallSha256': hashlib.sha256(merged).hexdigest().upper(),
    }
    if not apply:
        return actions
    if backup.exists():
        raise ValueError('backup already exists; inspect previous transaction before retrying')
    backup.mkdir(parents=True, mode=0o700)
    json_save(backup / 'cleanup-plan.json', actions)
    metadata = backup / 'metadata'
    metadata.mkdir()
    for name in ['inventory.json', 'journal.jsonl', 'summary.json', 'converted.json', 'remaining.json', 'duplicates.json', 'cleanup.json']:
        if (report / name).exists():
            shutil.copy2(report / name, metadata / name)
    removed = set(usernames) | {row[0] for row in short_files}
    replaced = removed | {'small.txt'}
    moves = []
    small_written = False
    try:
        # Retain the previous aggregate and its obsolete hash before replacing it.
        if existing:
            for original, dest in [(source / 'small.txt', backup / 'sources/small.txt'), (report / 'files/small.txt.sha1', backup / 'hashes/small.txt.sha1')]:
                if original.exists():
                    dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                    original.rename(dest)
                    moves.append((original, dest))
        # Verify the complete merged file before removing any input.
        save(source / 'small.txt', merged)
        small_written = True
        saved = (source / 'small.txt').read_bytes()
        if saved != merged or saved.count(b'\n') != line_count:
            raise ValueError('merged file verification failed')
        for name in sorted(removed):
            for original, dest in [(source / name, backup / 'sources' / name), (report / 'files' / (name + '.sha1'), backup / 'hashes' / (name + '.sha1'))]:
                if original.exists():
                    dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                    original.rename(dest)
                    moves.append((original, dest))
        # An interrupted worker may have one unpublished output: retain it too.
        for partial in (report / 'files').rglob('*.sha1.partial'):
            dest = backup / 'interrupted' / partial.relative_to(report / 'files')
            dest.parent.mkdir(parents=True, exist_ok=True)
            partial.rename(dest)
            moves.append((partial, dest))
        # A crash between publication and journaling must not poison resumption.
        active_records = {name: row for name, row in records.items() if name not in replaced}
        for item in plan['files']:
            name = item['file']
            output = report / 'files' / (name + '.sha1')
            if name not in replaced and output.exists() and active_records.get(name, {}).get('status') != 'converted':
                dest = backup / 'unrecorded' / (name + '.sha1')
                dest.parent.mkdir(parents=True, exist_ok=True)
                output.rename(dest)
                moves.append((output, dest))
        canonical = {}
        for name, row in active_records.items():
            key = (row['source']['bytes'], row['source']['sha256'])
            if row['status'] == 'converted':
                if key in canonical:
                    row['duplicateOf'] = canonical[key]
                else:
                    row.pop('duplicateOf', None)
                    canonical[key] = name
        plan['files'] = [row for row in plan['files'] if row['file'] not in replaced]
        info = snapshot(source / 'small.txt')
        plan['files'].append({'file': 'small.txt', 'bytes': info[2], 'snapshot': info})
        plan['files'].sort(key=lambda row: (row['bytes'], row['file']))
        plan['normalization'] = actions
        save(report / 'journal.jsonl', ''.join(json.dumps(row) + '\n' for row in active_records.values()).encode())
        json_save(report / 'inventory.json', plan)
        json_save(report / 'cleanup.json', actions)
        return actions
    except BaseException:
        # Normal errors restore exact originals and previous bookkeeping.
        if small_written:
            (source / 'small.txt').unlink()
        for original, dest in reversed(moves):
            dest.rename(original)
        for file in metadata.iterdir():
            shutil.copy2(file, report / file.name)
        # Renaming back changes ctime: refresh only the sources we restored.
        restored = json.loads((report / 'inventory.json').read_text())
        moved_sources = {str(original.relative_to(source)) for original, _ in moves if original.is_relative_to(source)}
        for row in restored['files']:
            if row['file'] in moved_sources:
                row['snapshot'] = snapshot(source / row['file'])
        json_save(report / 'inventory.json', restored)
        if not (metadata / 'cleanup.json').exists() and (report / 'cleanup.json').exists():
            (report / 'cleanup.json').unlink()
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ['source', 'report', 'backup', 'worker']:
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--under-lines', type=int, help='Merge ALL inventory lists below this exclusive threshold, extending a verified existing small.txt')
    args = parser.parse_args()
    result = consolidate(args.source, args.report, args.backup, args.worker, args.apply, args.under_lines)
    print(json.dumps(result, indent=2))
