import hashlib
import importlib.util
from pathlib import Path
import random
import tempfile

spec = importlib.util.spec_from_file_location('compact_index', Path(__file__).parents[1] / 'scripts/compact_index.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    h = lambda text: hashlib.sha1(text.encode()).digest()
    # Include multiple files, long line numbers, sparse and contiguous runs.
    records = sorted([(h('example'), 0, 1, 3), (h('example'), 0, 4, 2),
                      (h('example'), 0, 100, 1), (h('example'), 1, 2**40, 2),
                      (bytes(20), 1, 1, 1), (bytes([255]) * 20, 0, 1, 1)])
    files = ['dataset/master.txt', 'føø.txt']
    path = root / 'index.bin'
    report = module.build_index(path, files, records, reserve=0)
    assert report['uniqueHashes'] == 3 and report['occurrences'] == 10
    assert report['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    index = module.Index(path)
    assert index.lookup(h('example')) == {'count': 8, 'files': [
        {'file': files[0], 'count': 6, 'lineRanges': [[1, 5], [100, 100]]},
        {'file': files[1], 'count': 2, 'lineRanges': [[2**40, 2**40 + 1]]}]}
    assert index.lookup(h('absent')) is None
    assert index.lookup(bytes(20))['count'] == 1
    assert index.lookup(bytes([255]) * 20)['count'] == 1
    index.close()
    # Thousands of entries in one prefix exercise block offsets and binary search.
    rng = random.Random(4)
    hashes = sorted({b'\x12\x34\x50' + rng.randbytes(17) for _ in range(2000)})
    dense = root / 'dense.bin'
    module.build_index(dense, files, ((x, 0, i + 1, 1) for i, x in enumerate(hashes)), reserve=0)
    index = module.Index(dense)
    for i, digest in enumerate(hashes):
        assert index.lookup(digest)['files'][0]['lineRanges'] == [[i + 1, i + 1]]
    assert index.lookup(b'\x12\x34\x50' + bytes(17)) is None
    index.close()
    for bad in [records[::-1], [(h('x'), 0, 1, 3), (h('x'), 0, 2, 1)], [(b'x', 0, 1, 1)]]:
        try:
            module.build_index(root / 'bad.bin', files, bad, reserve=0)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid records accepted')
        assert not (root / 'bad.bin').exists() and not (root / 'bad.bin.partial').exists()
    try:
        module.build_index(root / 'space.bin', files, records, reserve=10**18)
    except RuntimeError:
        pass
    else:
        raise AssertionError('disk reserve bypassed')
    assert not (root / 'space.bin').exists()
    try:
        module.build_index(path, files, records, reserve=0)
    except FileExistsError:
        pass
    else:
        raise AssertionError('existing index overwritten')
print('Compact index: exact lookup, filenames, original line ranges, counts, prefix boundaries, ordering and disk guards passed.')
