"""Resume a verified RAM overlay's disk copy, without deleting either input.

Mount the completed RAM index and receipt read-only. Only a dedicated overlay
destination directory needs write access. Interrupted copies are rechecked
byte-for-byte against the source before appending. Low space waits in place.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time

from compact_index import Index
from finalize_inventory import save_receipt, sync_directory

CHUNK = 8 * 1024 * 1024


def regular(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('expected regular file')
    return os.fdopen(fd, 'r+b' if flags & os.O_RDWR else 'rb', buffering=0)


def snapshot(path):
    value = path.stat(follow_symlinks=False)
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def publish(source, target, reserve, wait, owner=None):
    if reserve < 0 or source.resolve() == target.resolve() or target.name == 'master.pwnidx':
        raise ValueError('invalid publication target or reserve')
    with regular(Path(str(source) + '.receipt.json'), os.O_RDONLY) as stream:
        data = stream.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError('receipt exceeds bound')
    receipt = json.loads(data)
    if (receipt.get('state') != 'verified' or receipt.get('savedProvenanceVerified') is not True
            or receipt.get('originalOrderHashChecksumsVerified') is not True
            or not re.fullmatch('[0-9a-f]{64}', receipt.get('sha256', ''))
            or not isinstance(receipt.get('bytes'), int) or receipt['bytes'] <= 0
            or receipt.get('occurrences') != receipt.get('originalLines')):
        raise ValueError('source has no complete verification receipt')
    before = snapshot(source)
    if before[2] != receipt['bytes']:
        raise ValueError('source size differs from receipt')
    staged = Path(str(target) + '.copy.partial')
    intent_path = Path(str(target) + '.publish.json')
    final_receipt = Path(str(target) + '.receipt.json')
    with regular(Path(str(target) + '.publish.lock'), os.O_RDWR | os.O_CREAT) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        intent = {'sourceReceipt': receipt, 'target': target.name}
        if intent_path.exists():
            with regular(intent_path, os.O_RDONLY) as stream:
                if json.load(stream) != intent:
                    raise ValueError('publication receipt changed')
        else:
            if target.exists() or staged.exists() or final_receipt.exists():
                raise FileExistsError('unrecorded publication artifacts')
            save_receipt(intent_path, intent)

        # A previous run may have linked the release but not finished cleanup.
        existing_release = target.exists()
        candidate = target if existing_release else staged
        complete_copy = candidate.exists() and candidate.stat().st_size == receipt['bytes']
        flags = os.O_RDONLY if existing_release or complete_copy else os.O_RDWR | os.O_CREAT
        with regular(source, os.O_RDONLY) as src, regular(candidate, flags) as dst:
            saved = os.fstat(dst.fileno()).st_size
            if saved > receipt['bytes']:
                raise ValueError('saved copy exceeds source size')
            compared = 0
            while compared < saved:
                block = src.read(min(CHUNK, saved - compared))
                if not block or dst.read(len(block)) != block:
                    raise ValueError('saved copy differs from source; nothing discarded')
                compared += len(block)
            if existing_release and saved != receipt['bytes']:
                raise ValueError('published index is incomplete')
            remaining = receipt['bytes'] - saved
            while remaining and shutil.disk_usage(target.parent).free < reserve + remaining + len(data) + 1024**2:
                wait('waiting_for_disk', saved, receipt['bytes'])
            while saved < receipt['bytes']:
                block = src.read(min(CHUNK, receipt['bytes'] - saved))
                if not block:
                    raise ValueError('source truncated')
                pending = memoryview(block)
                while pending:
                    if shutil.disk_usage(target.parent).free < reserve + len(pending):
                        wait('waiting_for_disk', saved, receipt['bytes'])
                        continue
                    try:
                        count = dst.write(pending)
                    except OSError as error:
                        if error.errno not in (errno.ENOSPC, errno.EDQUOT):
                            raise
                        wait('waiting_for_disk', saved, receipt['bytes'])
                        continue
                    if not count:
                        raise OSError('copy made no progress')
                    pending = pending[count:]
                    saved += count
                os.fsync(dst.fileno())
            if src.read(1) or snapshot(source) != before:
                raise ValueError('source changed during copy')
            dst.seek(0)
            if hashlib.file_digest(dst, 'sha256').hexdigest() != receipt['sha256']:
                raise ValueError('saved index checksum mismatch')
            index = Index(candidate)
            try:
                if index.unique != receipt['uniqueHashes']:
                    raise ValueError('saved unique count mismatch')
            finally:
                index.close()
            if owner is not None:
                os.fchown(dst.fileno(), owner, owner)
            os.fchmod(dst.fileno(), 0o400)
            os.fsync(dst.fileno())
        if final_receipt.exists():
            with regular(final_receipt, os.O_RDONLY) as stream:
                if json.load(stream) != receipt:
                    raise ValueError('published receipt differs')
        else:
            save_receipt(final_receipt, receipt)
        if not existing_release:
            os.link(staged, target)
            sync_directory(target.parent)
        if staged.exists():
            if not os.path.samestat(staged.stat(), target.stat()):
                raise ValueError('staged path is not the published inode')
            staged.unlink()
        sync_directory(target.parent)
    return {'state': 'published', 'bytes': receipt['bytes'], 'sha256': receipt['sha256'],
            'occurrences': receipt['occurrences'], 'sourceDeleted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('target', type=Path)
    parser.add_argument('--reserve-bytes', type=int, required=True,
                        help='explicit destination free-space floor, checked before and during copying')
    parser.add_argument('--owner', type=int, help='final index uid/gid when running the publisher as root')
    args = parser.parse_args()

    def wait(state, saved, total):
        print(json.dumps({'state': state, 'savedBytes': saved, 'totalBytes': total}), flush=True)
        time.sleep(30)

    print(json.dumps(publish(args.source, args.target, args.reserve_bytes, wait, args.owner)), flush=True)
