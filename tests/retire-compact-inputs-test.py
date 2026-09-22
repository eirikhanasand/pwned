import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


overlay, retirement = module('import-compact-overlay'), module('retire-compact-inputs')


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
print('Verified compact input retirement, corruption guard, resumption and reimport prevention passed.')
