import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from copy import deepcopy

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


overlay, retirement = module('import-compact-overlay'), module('retire-compact-inputs')
from compact_index import build_index


def meta(data, lines):
    return dict(bytes=len(data), lines=lines, newlines=data.count(b'\n'), terminated=data.endswith(b'\n'),
                sha256=hashlib.sha256(data).hexdigest().upper())


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory); (root / 'files').mkdir()
    plaintext = b'example\n'
    hashes = hashlib.sha1(b'example').hexdigest().upper().encode() + b'\n'
    mapping = struct.pack('<Q', 1)
    row = {'file': 'one.txt', 'source': meta(plaintext, 1), 'rawOutput': meta(hashes, 1),
           'output': meta(hashes, 1), 'lineMap': meta(mapping, 1), 'outputPath': 'files/one.sha1',
           'lineMapPath': 'files/one.lines', 'deduplicated': True}
    hp, mp = root / row['outputPath'], root / row['lineMapPath']
    hp.write_bytes(hashes); mp.write_bytes(mapping)
    (root / 'converted.json').write_text(json.dumps([row]))
    rows, plan = overlay.selection(root, 100)
    index = root / 'test.pwnidx'
    overlay.build(root, index, rows, plan, 10**9, 0)
    assert retirement.run(root, index)['plannedBytes'] == 49
    assert hp.exists() and mp.exists()
    mp.write_bytes(b'corrupt!')
    try:
        retirement.run(root, index)
        raise AssertionError('corrupted legacy input accepted')
    except ValueError: pass
    assert hp.exists() and mp.exists()
    mp.write_bytes(mapping)
    result = retirement.run(root, index, True)
    assert result['removedBytes'] == 49 and not hp.exists() and not mp.exists()
    assert retirement.run(root, index, True)['removedBytes'] == 0
    assert index.exists() and (root / 'converted.json').exists()
    assert not overlay.selection(root, 100)[0]
    assert json.loads((root / 'compacted.json').read_text())['one.txt']['state'] == 'retired'

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory); (root / 'files').mkdir()
    data = b'example\nexample\n'
    digest = hashlib.sha1(b'example').digest()
    raw = (digest.hex().upper().encode() + b'\n') * 2
    row = {'file': 'raw.txt', 'source': meta(data, 2), 'output': meta(raw, 2),
           'outputPath': 'files/raw.sha1', 'status': 'converted'}
    hp = root / row['outputPath']; hp.write_bytes(raw)
    (root / 'converted.json').write_text(json.dumps([row]))
    index = root / 'native.pwnidx'
    report = build_index(index, ['raw.txt', 'new.txt'], [(digest, 0, 1, 2), (digest, 1, 7, 1)], reserve=0)
    receipt = {**report, 'state': 'verified', 'savedProvenanceVerified': True,
               'originalSourceChecksumsVerified': True, 'preDeduplicationCountsVerified': True,
               'sources': [{'file': 'raw.txt', 'source': row['source'], 'uniqueHashes': 1},
                           {'file': 'new.txt', 'source': meta(b'example\n', 1), 'uniqueHashes': 1}]}
    rp = Path(str(index) + '.receipt.json'); rp.write_text(json.dumps(receipt))
    assert retirement.run(root, index)['sourceFiles'] == 1
    assert hp.exists()
    bad = deepcopy(receipt); bad['sources'][0]['source']['sha256'] = '0'*64
    rp.write_text(json.dumps(bad))
    try:
        retirement.run(root, index, True)
        raise AssertionError('source checksum mismatch accepted')
    except ValueError: pass
    assert hp.exists()
    rp.write_text(json.dumps(receipt))
    assert retirement.run(root, index, True)['removedBytes'] == len(raw)
    assert not hp.exists() and retirement.run(root, index, True)['removedBytes'] == 0
print('Verified compact input retirement, corruption guard, resumption and reimport prevention passed.')
