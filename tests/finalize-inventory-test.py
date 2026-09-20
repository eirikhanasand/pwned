import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

worker, driver = map(Path, sys.argv[1:3])
spec = importlib.util.spec_from_file_location('finalize', driver.with_name('finalize_inventory.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def native(*args):
    process = subprocess.run([str(worker), *map(str, args)], capture_output=True, text=True)
    if process.returncode:
        raise RuntimeError(process.stderr)
    return json.loads(process.stdout)


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    source, destination = root / 'source', root / 'hashes'
    source.mkdir()
    fixtures = {'empty.txt': b'', 'blank.txt': b'\n\n', 'mixed.txt': b'b\r\na\na\r\n\nlast\r',
                'other.txt': b'b\nb\na', 'parallel.txt': b'repeat\n' * 100005}
    for name, raw in fixtures.items():
        (source / name).write_bytes(raw)
    command = [sys.executable, str(driver), '--source', str(source), '--destination', str(destination), '--worker', str(worker), '--reserve', '0', '--threads', '2']
    subprocess.run(command, check=True, capture_output=True)
    subprocess.run(command + ['--deduplicate'], check=True, capture_output=True)
    summary = json.loads((destination / 'summary.json').read_text())
    assert summary['deduplicatedFiles'] == 5 and summary['originalFilesDeleted'] == 0
    assert summary['inputLinesConverted'] == summary['outputLinesVerified']
    assert summary['storedHashLines'] < summary['outputLinesVerified']
    for name, raw in fixtures.items():
        values = raw.split(b'\n') if raw else []
        if raw.endswith(b'\n'):
            values.pop()
        hashes = [hashlib.sha1(v.removesuffix(b'\r')).hexdigest().upper().encode() for v in values]
        unique = sorted(set(hashes))
        assert (destination / 'files' / (name + '.sha1')).read_bytes() == b''.join(h + b'\n' for h in unique)
        mapping = list(struct.iter_unpack('<Q', (destination / 'files' / (name + '.sha1.lines')).read_bytes()))
        assert [unique[line - 1] for (line,) in mapping] == hashes
        assert (source / name).read_bytes() == raw
    subprocess.run(command + ['--deduplicate', '--delete-verified-originals'], check=True, capture_output=True)
    assert not list(source.iterdir())
    subprocess.run(command + ['--deduplicate', '--delete-verified-originals'], check=True, capture_output=True)
    summary = json.loads((destination / 'summary.json').read_text())
    assert summary['originalFilesDeleted'] == 5 and summary['state'] == 'complete'
    assert subprocess.run(command, capture_output=True).returncode != 0

    direct_source, direct_destination = root / 'direct', root / 'direct-hashes'
    direct_source.mkdir()
    for name in ['first.txt', 'duplicate.txt']:
        (direct_source / name).write_bytes(b'same\nsame\n')
    direct_command = [sys.executable, str(driver), '--source', str(direct_source), '--destination', str(direct_destination), '--worker', str(worker), '--reserve', '0', '--deduplicate', '--delete-verified-originals']
    subprocess.run(direct_command, check=True, capture_output=True)
    direct_summary = json.loads((direct_destination / 'summary.json').read_text())
    assert direct_summary['originalFilesDeleted'] == direct_summary['storedHashLines'] == 2
    assert direct_summary['inputLinesConverted'] == direct_summary['outputLinesVerified'] == 4
    assert direct_summary['duplicateGroups'] == 1
    assert not list(direct_source.iterdir())

    # Failure before the receipt, between publications and after unlink must recover.
    for failure in ['counts', 'corrupt', 'publication', 'after-unlink', 'reserve', 'memory']:
        src, dest = root / failure, root / (failure + '-hashes')
        src.mkdir(); (dest / 'files').mkdir(parents=True)
        original = src / 'test.txt'
        original.write_bytes(b'one\none\ntwo\n')
        output = dest / 'files/test.txt.sha1'
        converted = native('convert', original, output, 0, 2)
        record = {'file': 'test.txt', 'status': 'converted', **converted}
        s = original.stat()
        item = {'file': 'test.txt', 'snapshot': [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]}
        if failure == 'counts':
            record['output'] = {**record['output'], 'lines': 2}
        if failure == 'corrupt':
            output.write_bytes(b'0' * 123)
        replace = Path.replace
        unlink = Path.unlink
        def fail_replace(self, target):
            if str(self).endswith('.lines.partial'):
                raise OSError('injected publication failure')
            return replace(self, target)
        def fail_unlink(self, *args, **kwargs):
            result = unlink(self, *args, **kwargs)
            if self == original:
                raise OSError('injected crash after unlink')
            return result
        if failure == 'publication':
            Path.replace = fail_replace
        if failure == 'after-unlink':
            Path.unlink = fail_unlink
        try:
            module.finalize(item, record, src, dest, native, 10**18 if failure == 'reserve' else 0,
                            1 if failure == 'memory' else 1_000_000_000, True)
            raise AssertionError('failure not caught')
        except (RuntimeError, OSError):
            pass
        finally:
            Path.replace, Path.unlink = replace, unlink
        if failure != 'after-unlink':
            assert original.read_bytes() == b'one\none\ntwo\n'
        if failure in ['publication', 'after-unlink', 'reserve', 'memory']:
            result = module.finalize(item, record, src, dest, native, 0, 1_000_000_000, True)
            assert result['originalDeleted'] and result['rawOutput']['lines'] == 3 and result['output']['lines'] == 2

    # A live legacy manifest blocks deletion before any file is touched.
    (source / 'lookup.txt').write_bytes(b'metadata')
    blocked = subprocess.run(command + ['--deduplicate', '--delete-verified-originals'], capture_output=True, text=True)
    assert blocked.returncode != 0 and 'legacy lookup manifests' in blocked.stderr
print('Finalization passed: pre-dedupe counts, sorted unique hashes, original-line mapping, existing/new conversions, verified deletion, resumption, corruption, memory/disk guards, transaction crash recovery and legacy-service protection.')
