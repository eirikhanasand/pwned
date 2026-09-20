import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

worker, driver = sys.argv[1:3]


def execute(*args, succeeds=True):
    result = subprocess.run([worker, *map(str, args)], capture_output=True, text=True)
    assert (result.returncode == 0) == succeeds, result.stderr
    return json.loads(result.stdout) if result.returncode == 0 else result.stderr


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    source = root / 'source'
    source.mkdir()
    fixtures = [b'', b'\n', b'HelloWorld', b'HelloWorld\n', b'a\r\n\r\nb\r', b' a \n\x00\xff\n', 'æøå\n'.encode(), b'x' * (9 * 1024 * 1024) + b'\nend']
    for index, data in enumerate(fixtures):
        path = source / f'{index}.txt'
        path.write_bytes(data)
        output = root / f'{index}.sha1'
        result = execute('convert', path, output, 0, 2)
        rows = data.split(b'\n')
        if not data or data.endswith(b'\n'):
            rows.pop()
        expected = b'\n'.join(hashlib.sha1(row[:-1] if row.endswith(b'\r') else row).hexdigest().upper().encode() for row in rows)
        if data.endswith(b'\n'):
            expected += b'\n'
        assert output.read_bytes() == expected
        assert result['source']['lines'] == result['output']['lines'] == len(rows)
        assert result['source']['newlines'] == result['output']['newlines'] == data.count(b'\n')
        assert result['output']['sha256'] == hashlib.sha256(expected).hexdigest().upper()
        assert path.read_bytes() == data
        execute('convert', path, output, 0, 2, succeeds=False)
    # Duplicate content, metadata exclusion, and deterministic smallest-first order.
    (source / 'duplicate.txt').write_bytes(fixtures[3])
    (source / 'lookup.txt').write_bytes(b'not a password inventory')
    (source / 'external.txt').symlink_to(source / '3.txt')
    (source / '.git').mkdir()
    (source / '.git' / 'hidden.txt').write_bytes(b'not inventory')
    destination = root / 'hashes'
    command = [sys.executable, driver, '--source', str(source), '--destination', str(destination), '--worker', worker, '--reserve', '0', '--threads', '2']
    subprocess.run(command, check=True, capture_output=True)
    summary = json.loads((destination / 'summary.json').read_text())
    assert summary['state'] == 'complete' and summary['totalFiles'] == 9
    assert summary['inputLinesConverted'] == summary['outputLinesVerified']
    assert summary['duplicateGroups'] == 1
    assert (destination / 'files/3.txt.sha1').stat().st_ino == (destination / 'files/duplicate.txt.sha1').stat().st_ino
    journal = [json.loads(line) for line in (destination / 'journal.jsonl').read_text().splitlines()]
    assert [row['source']['bytes'] for row in journal] == sorted(row['source']['bytes'] for row in journal)
    subprocess.run(command, check=True, capture_output=True)  # Resume verifies saved outputs.
    blocked = root / 'blocked'
    subprocess.run([sys.executable, driver, '--source', str(source), '--destination', str(blocked), '--worker', worker, '--reserve', str(10**18)], check=True, capture_output=True)
    status = json.loads((blocked / 'summary.json').read_text())
    assert status['state'] == 'blocked_space' and status['convertedFiles'] == 0
    assert status['remainingFiles'] == 9 and status['duplicatesAuditComplete']
    (destination / 'files/0.txt.sha1').chmod(0o600)
    (destination / 'files/0.txt.sha1').write_bytes(b'corrupt')
    assert subprocess.run(command, capture_output=True).returncode != 0
print('Inventory conversion: exact hashes, line counts, binary/CRLF/blank/final lines, duplicate files, resume, corruption, disk reserve and source preservation passed.')
