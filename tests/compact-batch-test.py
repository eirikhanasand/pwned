"""Native multi-file provenance and complete migration/retirement regressions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from compact_index import Index, build_index

spec = importlib.util.spec_from_file_location('remaining', Path(__file__).parents[1] / 'scripts/run-remaining-inventory.py')
remaining = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remaining)
builder, scanner = map(lambda p: str(Path(p).resolve()), sys.argv[1:3])


def meta(data):
    return {'bytes': len(data), 'lines': data.count(b'\n') + bool(data and not data.endswith(b'\n')),
            'newlines': data.count(b'\n'), 'terminated': bool(data) and data.endswith(b'\n'),
            'sha256': hashlib.sha256(data).hexdigest().upper()}


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source, inventory, output, work = (root / s for s in ('source', 'inventory', 'output', 'work'))
    for p in (source, inventory, output, work):
        p.mkdir()
    fixture = {'empty-first.txt': b'', 'a.txt': b'a\na\nb\r\n', 'b.txt': b'\na\nx\x00\xff\n',
               'c.txt': b'a\r', 'empty-last.txt': b''}
    items, expected = [], {}
    for name, data in fixture.items():
        p = source / name
        p.write_bytes(data)
        items.append({'file': name, 'bytes': len(data), 'snapshot': remaining.snapshot(p)})
        lines = data.split(b'\n')
        if not data or data.endswith(b'\n'):
            lines.pop()
        for line, value in enumerate(lines, 1):
            if value.endswith(b'\r'): value = value[:-1]
            expected.setdefault(hashlib.sha1(value).digest(), {}).setdefault(name, []).append(line)
    (inventory / 'inventory.json').write_text(json.dumps({'files': items}))
    args = remaining.argparse.Namespace(source=source, inventory=inventory, output=output, work=work,
                                       builder=Path(builder), scanner=Path(scanner), covered_index=[],
                                       covered_receipt=[], memory_bytes=20_000_000_000, reserve_bytes=0,
                                       threads=2, owner=None, release_sources_from_ram=False)
    if os.environ.get('TEST_RAM_RETIREMENT'):
        args.release_sources_from_ram = True
        disk_usage = remaining.shutil.disk_usage
        def constrained(path):
            value = disk_usage(path)
            # Force the deletion-before-copy branch only for this fixture.
            if Path(path) == output and any(source.iterdir()):
                return value._replace(free=0)
            return value
        remaining.shutil.disk_usage = constrained
    remaining.run(args)
    if os.environ.get('TEST_RAM_RETIREMENT'):
        remaining.shutil.disk_usage = disk_usage
        journal = json.loads((output / 'remaining.retirement.json').read_text())
        assert all(r['ramOnlyAtDeletion'] for r in journal['files'].values())
    assert not any(source.iterdir())
    report = json.loads((output / 'remaining.report.json').read_text())
    assert report['deletedOriginalFiles'] == len(fixture)
    assert report['originalLines'] == sum(meta(x)['lines'] for x in fixture.values())
    index = Index(output / 'remaining.pwnidx')
    for digest, expected_files in expected.items():
        result = index.lookup(digest)
        actual = {x['file']: [n for first, last in x['lineRanges'] for n in range(first, last + 1)]
                  for x in result['files']}
        assert actual == expected_files, (actual, expected_files)
    assert index.unique == len(expected)
    assert sum(n for _, _, _, n in index.records()) == report['originalLines']
    index.close()
    assert {r['file']: r['uniqueHashes'] for r in report['files']} == {
        name: sum(name in files for files in expected.values()) for name in fixture}
    # Resume after completion, including durable deletion intents, never rebuilds.
    remaining.run(args)
    assert json.loads((output / 'remaining.status.json').read_text())['state'] == 'complete'

    # Exact removal refuses changed content and path escapes, even with a receipt.
    p = source / 'changed.txt'; p.write_bytes(b'old\n')
    entry = {'file': p.name, 'source': meta(b'old\n'), 'snapshot': remaining.snapshot(p)}
    p.write_bytes(b'new\n')
    journal = {'path': output / 'test-retirement.json', 'files': {}}
    try:
        remaining.retire_source(source, entry, Path(scanner), journal, 'a'*64, True)
        raise AssertionError('changed original deleted')
    except ValueError:
        pass
    assert p.exists() and not journal['files']
    for name in ('../outside', '/absolute'):
        try:
            remaining.safe_path(source, name)
            raise AssertionError('unsafe source accepted')
        except ValueError:
            pass
    # A RAM-only source retirement is recoverable through its intent only.
    entry = {'file': p.name, 'source': meta(b'new\n'), 'snapshot': remaining.snapshot(p)}
    remaining.retire_source(source, entry, Path(scanner), journal, 'b'*64, True)
    assert not p.exists() and journal['files'][p.name]['ramOnlyAtDeletion']
    remaining.retire_source(source, entry, Path(scanner), journal, 'b'*64, False)

    # Native batch source checksum and logical-line count failures retain inputs.
    for mode in ('bad-sha', 'bad-count', 'duplicate-name'):
        folder = root / mode; folder.mkdir()
        src = folder / 'input'; src.write_bytes(b'a\na\nb')
        profile = meta(src.read_bytes())
        if mode == 'bad-sha': profile['sha256'] = '0'*64
        if mode == 'bad-count': profile['lines'] += 1
        row = '\t'.join([str(src), 'test.txt', str(profile['lines']), str(profile['newlines']),
                         str(profile['bytes']), profile['sha256'].lower()]) + '\n'
        if mode == 'duplicate-name': row += row
        manifest = folder / 'manifest'; manifest.write_text(row)
        result = subprocess.run([builder, str(manifest), str(folder / 'out'), 'batch',
                                 str(profile['lines']), str(profile['newlines']), str(manifest.stat().st_size),
                                 hashlib.sha256(manifest.read_bytes()).hexdigest(), str(20_000_000_000), '0', '2'],
                                capture_output=True)
        assert result.returncode and src.exists() and not (folder / 'out').exists(), mode
print('Batch conversion: hashes, every file/line/count, dedupe, durable publication, exact retirement, recovery and corruption guards passed.')
