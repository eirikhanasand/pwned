import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import zlib

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from compact_index import build_index, prefix_of

spec = importlib.util.spec_from_file_location('service', Path(__file__).parents[1] / 'scripts/serve-compact-index.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'fixture.pwnidx'
    digest = hashlib.sha1(b'fixture').digest()
    build_index(path, ['one.txt', 'two.txt'], [(digest, 0, 12, 2), (digest, 1, 47, 1)], reserve=0)
    with service.PrefixServer(('127.0.0.1', 0), path) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            assert json.load(urllib.request.urlopen(base + '/health')) == {'ok': True}
            prefix = digest.hex()[:5]
            with urllib.request.urlopen(base + '/range/' + prefix) as response:
                assert response.headers['Content-Type'] == service.CONTENT_TYPE
                assert response.headers['Cache-Control'] == 'no-store'
                body = response.read()
            magic, length, actual_prefix = service.ENVELOPE.unpack_from(body)
            assert magic == b'PWNPRF01' and actual_prefix == prefix_of(digest)
            assert json.loads(body[16:16+length]) == ['one.txt', 'two.txt']
            block = body[16+length:]
            raw = zlib.decompress(block[4:])
            assert len(raw) == struct.unpack_from('<I', block)[0]
            assert raw[4:22] == digest[2:]
            assert server.index.lookup(digest) == {'count': 3, 'files': [
                {'file': 'one.txt', 'count': 2, 'lineRanges': [[12, 13]]},
                {'file': 'two.txt', 'count': 1, 'lineRanges': [[47, 47]]},
            ]}
            empty_prefix = f'{(int(prefix,16)+1) % (1<<20):05X}'
            empty = urllib.request.urlopen(base + '/range/' + empty_prefix).read()
            assert len(empty) == 16 + length
            for invalid in ('/range/' + digest.hex(), '/range/secret', '/range/12345?hash=secret', '/range/1234', '/range/G1234', '/'):
                try:
                    urllib.request.urlopen(base + invalid)
                    raise AssertionError('invalid input accepted')
                except urllib.error.HTTPError as error:
                    assert error.code == 400
        finally:
            server.shutdown()
            worker.join()
print('Compact prefix service checks passed.')
