"""Read-only profile counts and exact normalization agree with conversion."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

worker = sys.argv[1]


def varbytes(value):
    return max(1, (value.bit_length() + 6) // 7)


with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'source.txt'
    fixtures = [b'', b'\n', b'\n\n', b'a', b'a\na\nb\n', b'b\na\n',
                b'a\r\na\nb\r', b' a\n\x00\xff\n', b'z\n' * 1000,
                b'x' * (9 * 1024 * 1024) + b'\nz']
    for data in fixtures:
        path.write_bytes(data)
        before = path.stat()
        result = subprocess.run([worker, str(path)], text=True, capture_output=True, check=True)
        profile = json.loads(result.stdout.splitlines()[-1])
        rows = data.split(b'\n')
        if not data or data.endswith(b'\n'):
            rows.pop()
        rows = [r[:-1] if r.endswith(b'\r') else r for r in rows]
        runs = []
        for i, row in enumerate(rows):
            if not i or row != rows[i - 1]:
                runs.append([i + 1, 1])
            else:
                runs[-1][1] += 1
        assert profile['state'] == 'complete'
        assert profile['lines'] == len(rows)
        assert profile['newlines'] == data.count(b'\n')
        assert profile['adjacentRuns'] == len(runs)
        assert profile['orderingViolations'] == sum(a > b for a, b in zip(rows, rows[1:]))
        assert profile['runPositionAndLengthVarintBytes'] == sum(varbytes(a) + varbytes(b) for a, b in runs)
        assert profile['sha256'] == hashlib.sha256(data).hexdigest()
        assert profile['processedBytes'] == len(data)
        assert path.read_bytes() == data
        assert path.stat().st_mtime_ns == before.st_mtime_ns
    link = Path(directory) / 'link.txt'
    link.symlink_to(path)
    assert subprocess.run([worker, str(link)], capture_output=True).returncode != 0
print('Read-only sizing: counts, duplicate runs, order, CRLF, binary, long lines, checksums and symlink rejection passed.')
