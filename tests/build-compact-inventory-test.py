"""End-to-end native builder tests, including live disk-space pause/resume.

Run against a binary compiled with -DPWNED_TESTING. Production builds omit
that macro and cannot override disk-space accounting.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('compact_index', Path(__file__).parents[1] / 'scripts/compact_index.py')
index_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(index_module)
worker = str(Path(sys.argv[1]).resolve())
production = '--production' in sys.argv
if not production: subprocess.run([worker, '--test-lines'], check=True)


def arguments(source, output, data, threads=4):
    return [worker, str(source), str(output), 'fixtures/source.txt',
            str(data.count(b'\n') + bool(data and not data.endswith(b'\n'))),
            str(data.count(b'\n')), str(len(data)), hashlib.sha256(data).hexdigest(),
            str(5 * 1024**3), '10000000', str(threads)]


def rows_of(data):
    rows = data.split(b'\n')
    if not data or data.endswith(b'\n'):
        rows.pop()
    return [r[:-1] if r.endswith(b'\r') else r for r in rows]


def check_fixture(folder, data, threads=4):
    source, output = folder / 'source.txt', folder / 'index.bin'
    source.write_bytes(data)
    before = source.stat()
    result = subprocess.run(arguments(source, output, data, threads), capture_output=True, text=True, check=True)
    report = json.loads(result.stdout.splitlines()[-1])
    expected = {}
    for line, value in enumerate(rows_of(data), 1):
        digest = hashlib.sha1(value).digest()
        expected.setdefault(digest, []).append(line)
    assert report['state'] == 'complete'
    assert report['hashedLines'] == report['verifiedLines'] == len(rows_of(data))
    assert report['uniqueHashes'] == len(expected)
    assert report['preDeduplicationCountsVerified'] and report['savedProvenanceVerified']
    assert not report['originalDeleted']
    assert not Path(str(output) + '.partial').exists()
    assert report['indexSha256'] == hashlib.sha256(output.read_bytes()).hexdigest()
    index = index_module.Index(output)
    try:
        assert index.unique == len(expected)
        for digest, lines in expected.items():
            match = index.lookup(digest)
            assert match['count'] == len(lines)
            assert match['files'][0]['file'] == 'fixtures/source.txt'
            assert match['files'][0]['count'] == len(lines)
            actual = [line for start, end in match['files'][0]['lineRanges'] for line in range(start, end + 1)]
            assert actual == lines
        absent = hashlib.sha1(b'not-a-fixture-' + data[:40]).digest()
        if absent not in expected:
            assert index.lookup(absent) is None
    finally:
        index.close()
    assert source.read_bytes() == data and source.stat().st_mtime_ns == before.st_mtime_ns
    # Existing releases must never be overwritten.
    repeat = subprocess.run(arguments(source, output, data), capture_output=True)
    assert repeat.returncode != 0 and hashlib.sha256(output.read_bytes()).hexdigest() == report['indexSha256']


def wait_status(output, process, wanted):
    path = Path(str(output) + '.status.json')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if path.exists():
            value = json.loads(path.read_text())
            if value['state'] == wanted:
                return value
        if process.poll() is not None:
            raise AssertionError(process.communicate())
        time.sleep(.05)
    raise AssertionError('status timeout')


with tempfile.TemporaryDirectory(prefix='compact-builder-tests-') as temporary:
    root = Path(temporary)
    fixtures = [b'', b'\n', b'\n\n', b'a', b'a\na\nb\n', b'b\na\nb\na',
                b'a\r\na\nb\r', b' a\n\x00\xff\n', b'z\n' * 2000]
    randomizer = random.Random(42)
    fixtures.append(b'\n'.join(str(randomizer.randrange(3000)).encode() for _ in range(15000)))
    # Cross the 64 MiB input batch boundary, with CRLF and an unterminated tail.
    fixtures.append(b'x' * (33 * 1024**2) + b'\r\n' + b'y' * (33 * 1024**2) + b'\nx\r')
    for i, data in enumerate(fixtures):
        folder = root / str(i)
        folder.mkdir()
        check_fixture(folder, data)

    for mode in ('bad-count', 'bad-checksum', 'small-budget', 'symlink', 'existing-partial', 'oversized-line'):
        folder = root / mode; folder.mkdir()
        source, output = folder / 'source.txt', folder / 'index.bin'
        data = b'x' * (65 * 1024**2) + b'\n' if mode == 'oversized-line' else b'one\ntwo\n'
        source.write_bytes(data)
        args = arguments(source, output, data)
        if mode == 'bad-count': args[4] = '3'
        elif mode == 'bad-checksum': args[7] = '0' * 64
        elif mode == 'small-budget': args[8] = '1000'
        elif mode == 'symlink':
            link = folder / 'link.txt'; link.symlink_to(source); args[1] = str(link)
        elif mode == 'existing-partial': Path(str(output) + '.partial').write_bytes(b'existing partial')
        assert subprocess.run(args, capture_output=True).returncode != 0, mode
        assert not output.exists() and source.read_bytes() == data

    for mode in ('pause-resume', 'pause-mutate', 'pause-midwrite'):
        if production: break
        mutate = mode == 'pause-mutate'
        folder = root / mode; folder.mkdir()
        source, output, space = folder / 'source.txt', folder / 'index.bin', folder / 'space'
        data = b'one\ntwo\none\n'
        if mode == 'pause-midwrite': data += b''.join(str(i).encode() + b'\n' for i in range(2000))
        source.write_bytes(data)
        space.write_text(str(10000000 + 24 + len('["fixtures/source.txt"]') + (2**20 + 1) * 8 + 100) if mode == 'pause-midwrite' else '0')
        env = dict(os.environ, PWNED_TEST_SPACE_FILE=str(space))
        process = subprocess.Popen(arguments(source, output, data), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            status = wait_status(output, process, 'waiting_for_disk')
            assert status['hashedLines'] == data.count(b'\n') and process.poll() is None
            if mode == 'pause-midwrite':
                assert status['writtenBytes'] > 8 * 1024**2
                assert Path(str(output) + '.partial').exists()
            assert source.read_bytes() == data and not output.exists()
            # A concurrent builder cannot take the output lock.
            assert subprocess.run(arguments(source, output, data), env=env, capture_output=True).returncode != 0
            assert json.loads(Path(str(output) + '.status.json').read_text())['state'] == 'waiting_for_disk'
            if mutate: source.write_bytes(b'changed\n')
            replacement = space.with_suffix('.new'); replacement.write_text(str(10**12)); replacement.replace(space)
            stdout, stderr = process.communicate(timeout=30)
            if mutate:
                assert process.returncode != 0 and not output.exists(), (stdout, stderr)
                assert 'source snapshot changed' in stderr
            else:
                assert process.returncode == 0, (stdout, stderr)
                index = index_module.Index(output)
                assert index.lookup(hashlib.sha1(b'one').digest())['count'] == 2
                index.close()
                assert source.read_bytes() == data
        finally:
            if process.poll() is None: process.kill(); process.wait()
print('Native builder fixtures and guards passed.' if production else 'Native builder: exact hashes/counts/provenance, duplicates, CRLF/binary/long lines, 40-bit lines, guards, locks and disk pause/resume passed.')
