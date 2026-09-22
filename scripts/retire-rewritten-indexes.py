"""Retire exact source indexes only after their verified replacement is serving."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from finalize_inventory import save_receipt, sync_directory


def snapshot(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def checked(path, expected):
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size != expected['bytes']:
        raise ValueError('unexpected index file: ' + str(path))
    with path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected['sha256']:
            raise ValueError('index checksum mismatch: ' + str(path))
    if snapshot(before) != snapshot(path.stat(follow_symlinks=False)):
        raise ValueError('index changed during verification')
    return before


def retire(output, sources, mounts, apply=False):
    output = Path(output).absolute()
    receipt = json.loads(Path(str(output) + '.receipt.json').read_text())
    if not receipt.get('physicalDeduplication') or not receipt.get('savedRecordsVerified') or receipt.get('state') != 'verified':
        raise ValueError('replacement is not fully verified')
    checked(output, receipt)
    paths = [Path(source).absolute() for source in sources]
    expected = {Path(row['path']).name: row for row in receipt['sources']}
    if len(paths) != len(expected) or {p.name for p in paths} != set(expected) or len(set(paths)) != len(paths) or output in paths:
        raise ValueError('retirement inputs differ from replacement receipt')
    if str(output) not in mounts or any(str(p) in mounts for p in paths):
        raise ValueError('lookup must serve only the replacement, not its old inputs')
    with Path(str(output) + '.retirement.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report_path = Path(str(output) + '.retirement.json')
        prior = json.loads(report_path.read_text()) if report_path.exists() else None
        report = {'replacement': str(output), 'replacementSha256': receipt['sha256'],
                  'sources': [{'path': str(p), 'sha256': expected[p.name]['sha256'],
                               'bytes': expected[p.name]['bytes']} for p in paths], 'state': 'planned'}
        if prior and any(prior.get(k) != report[k] for k in ('replacement', 'replacementSha256', 'sources')):
            raise ValueError('retirement receipt changed')
        snapshots = {}
        for path in paths:
            if path.exists():
                snapshots[path] = checked(path, expected[path.name])
            elif not prior or prior.get('state') not in ('retiring', 'retired'):
                raise ValueError('source missing without recorded retirement intent')
        if apply:
            report['state'] = 'retiring'
            save_receipt(report_path, report)
            for path, before in snapshots.items():
                if snapshot(path.stat(follow_symlinks=False)) != snapshot(before):
                    raise ValueError('source changed before retirement')
                path.unlink()
                sync_directory(path.parent)
            report['state'] = 'retired'
            save_receipt(report_path, report)
        return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    parser.add_argument('--retire', action='store_true')
    parser.add_argument('replacement', type=Path)
    parser.add_argument('sources', type=Path, nargs='+')
    args = parser.parse_args()
    container, = json.loads(subprocess.check_output(['docker', 'inspect', args.container]))
    if not container['State']['Running'] or container['State'].get('Health', {}).get('Status') != 'healthy':
        raise ValueError('lookup container is not healthy')
    mounts = {m['Source'] for m in container['Mounts'] if m['Type'] == 'bind'}
    print(json.dumps(retire(args.replacement, args.sources, mounts, args.retire)))
