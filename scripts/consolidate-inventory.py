#!/usr/bin/env python3
"""Remove username-only lists and merge one-record password lists, recoverably."""
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


def consolidate(source, report, backup, worker, apply=False):
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
    if (source / 'small.txt').exists() or any(row['file'] == 'small.txt' for row in plan['files']):
        raise ValueError('small.txt already exists; refusing to overwrite it')
    usernames, single, mixed = [], [], []
    for row in plan['files']:
        name = row['file']
        path = source / name
        if snapshot(path) != row['snapshot']:
            raise ValueError('source changed: ' + name)
        basename = path.name.lower()
        if re.search(r'users?|usernames?|userlist', basename) and 'password' not in basename:
            usernames.append(name)
            continue
        if re.search(r'user', basename) and 'password' in basename:
            mixed.append(name)
            continue
        if path.name in HASH_FIXTURES:
            continue
        old = records.get(name)
        if old:
            count = old['source']['lines']
        else:
            with path.open('rb') as stream:
                prefix = stream.read(65536)
            # Two LF characters, or data after the first LF, prove >1 record.
            first = prefix.find(b'\n')
            if first >= 0 and (first < len(prefix) - 1 or row['bytes'] > len(prefix)):
                continue
            count = json.loads(subprocess.check_output([str(worker), 'scan', str(path)]))['lines']
        if count == 1:
            if row['bytes'] > 1024 * 1024:
                raise ValueError('unusually large single record needs review: ' + name)
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest().upper()
            if old and digest != old['source']['sha256']:
                raise ValueError('single-record checksum changed: ' + name)
            value = raw[:-1] if raw.endswith(b'\n') else raw
            if value.endswith(b'\r'):
                value = value[:-1]
            if b'\n' in value:
                raise ValueError('single-record validation failed: ' + name)
            single.append((name, value, digest))
    single.sort(key=lambda row: row[0])
    merged = b''.join(value + b'\n' for _, value, _ in single)
    if not single:
        raise ValueError('no one-record password files found')
    actions = {
        'usernameFilesRemoved': sorted(usernames),
        'mergedFiles': [{'file': name, 'sourceSha256': digest, 'originalLine': 1, 'smallLine': index + 1} for index, (name, _, digest) in enumerate(single)],
        'mixedListsPreserved': mixed,
        'hashFixturesPreserved': sorted(HASH_FIXTURES & {Path(row['file']).name for row in plan['files']}),
        'smallFile': 'small.txt', 'smallLines': len(single),
        'duplicatesPreserved': True, 'backupDirectory': str(backup),
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
    for name in ['inventory.json', 'journal.jsonl', 'summary.json', 'converted.json', 'remaining.json', 'duplicates.json']:
        if (report / name).exists():
            shutil.copy2(report / name, metadata / name)
    removed = set(usernames) | {name for name, _, _ in single}
    moves = []
    try:
        # Verify the complete merged file before removing any input.
        save(source / 'small.txt', merged)
        saved = (source / 'small.txt').read_bytes()
        if saved != merged or saved.count(b'\n') != len(single):
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
        active_records = {name: row for name, row in records.items() if name not in removed}
        for item in plan['files']:
            name = item['file']
            output = report / 'files' / (name + '.sha1')
            if name not in removed and output.exists() and active_records.get(name, {}).get('status') != 'converted':
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
        plan['files'] = [row for row in plan['files'] if row['file'] not in removed]
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
        for original, dest in reversed(moves):
            dest.rename(original)
        if (source / 'small.txt').exists():
            (source / 'small.txt').unlink()
        for file in metadata.iterdir():
            shutil.copy2(file, report / file.name)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ['source', 'report', 'backup', 'worker']:
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    result = consolidate(args.source, args.report, args.backup, args.worker, args.apply)
    print(json.dumps(result, indent=2))
