import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

worker, driver, cleanup = sys.argv[1:4]
spec = importlib.util.spec_from_file_location('cleanup', cleanup)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    source, report, backup = root / 'source', root / 'report', root / 'backup'
    source.mkdir()
    files = {
        'router_default-users.txt': b'root\nadmin\n',
        'Oracle EBS userlist.txt': b'system\n',
        'first_default-passwords.txt': b'secret',
        'second_default-passwords.txt': b'secret\r\n',
        'der-postillon.txt': b'phrase\n',
        'haval160,3.txt': b'test:hash\n',
        'combined_usernames-and-passwords.txt': b'keep\n',
        'multi.txt': b'a\nb\n',
        'unprocessed.txt': b'last',
        'empty.txt': b'',
        'ninety-nine.txt': b'\r\n' + b'duplicate\r\n' * 97 + b'last\r',
        'one-hundred.txt': b'keep\n' * 99 + b'last',
        'one-hundred-lf.txt': b'keep\n' * 100,
    }
    for name, data in files.items():
        (source / name).write_bytes(data)
    command = [sys.executable, driver, '--source', str(source), '--destination', str(report), '--worker', worker, '--reserve', '0', '--threads', '2']
    subprocess.run(command, check=True, capture_output=True)
    rows = [json.loads(line) for line in (report / 'journal.jsonl').read_text().splitlines()]
    (report / 'journal.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows if row['file'] != 'unprocessed.txt'))
    (report / 'files/multi.txt.sha1.partial').write_bytes(b'unfinished')
    preview = module.consolidate(source, report, backup, Path(worker))
    assert len(preview['usernameFilesRemoved']) == 2
    assert preview['smallLines'] == 4 and not backup.exists()
    result = module.consolidate(source, report, backup, Path(worker), True)
    assert (source / 'small.txt').read_bytes() == b'phrase\nsecret\nsecret\nlast\n'
    assert (backup / 'interrupted/multi.txt.sha1.partial').read_bytes() == b'unfinished'
    removed = result['usernameFilesRemoved'] + [row['file'] for row in result['mergedFiles']]
    for name in removed:
        assert not (source / name).exists()
        assert not (report / 'files' / (name + '.sha1')).exists()
        assert (backup / 'sources' / name).read_bytes() == files[name]
    for name in set(files) - set(removed):
        assert (source / name).read_bytes() == files[name]
    plan = json.loads((report / 'inventory.json').read_text())
    assert len(plan['files']) == 8
    subprocess.run(command, check=True, capture_output=True)
    summary = json.loads((report / 'summary.json').read_text())
    assert summary['state'] == 'complete' and summary['sourceInventoryNormalized']
    records = [json.loads(line) for line in (report / 'journal.jsonl').read_text().splitlines()]
    small = next(row for row in records if row['file'] == 'small.txt')
    assert small['source']['lines'] == small['output']['lines'] == 4
    try:
        module.consolidate(source, report, root / 'second-backup', Path(worker), True)
        raise AssertionError('must refuse overwriting small.txt')
    except ValueError:
        pass
    # The expanded mode includes mixed lists and fixtures and preserves old provenance.
    old_small = (source / 'small.txt').read_bytes()
    old_hash = (report / 'files/small.txt.sha1').read_bytes()
    rows = [json.loads(line) for line in (report / 'journal.jsonl').read_text().splitlines()]
    (report / 'journal.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows if row['file'] != 'ninety-nine.txt'))
    extended_backup = root / 'extended-backup'
    preview = module.consolidate(source, report, extended_backup, Path(worker), under_lines=100)
    assert preview['changesThisRun']['addedLines'] == 103
    assert len(preview['changesThisRun']['mergedFiles']) == 5
    assert preview['smallLines'] == 107
    assert preview['mergedFiles'][:4] == result['mergedFiles']
    assert not extended_backup.exists() and (source / 'small.txt').read_bytes() == old_small
    # Force a late transaction failure and verify the aggregate, originals and metadata recover.
    original_save = module.json_save
    def fail_cleanup(path, data):
        if path == report / 'cleanup.json':
            raise OSError('injected metadata failure')
        original_save(path, data)
    module.json_save = fail_cleanup
    try:
        module.consolidate(source, report, root / 'failed-backup', Path(worker), True, 100)
        raise AssertionError('injected failure did not stop cleanup')
    except OSError:
        pass
    finally:
        module.json_save = original_save
    assert (source / 'small.txt').read_bytes() == old_small
    assert (report / 'files/small.txt.sha1').read_bytes() == old_hash
    for name in preview['changesThisRun']['mergedFiles']:
        assert (source / name).read_bytes() == files[name]
    extended = module.consolidate(source, report, extended_backup, Path(worker), True, 100)
    new_small = (source / 'small.txt').read_bytes()
    assert new_small.startswith(old_small)
    assert (extended_backup / 'sources/small.txt').read_bytes() == old_small
    assert (extended_backup / 'hashes/small.txt.sha1').read_bytes() == old_hash
    assert not (report / 'files/small.txt.sha1').exists()
    assert json.loads((extended_backup / 'metadata/cleanup.json').read_text()) == result
    assert extended['previousBackupDirectories'] == [str(backup)]
    for row in extended['mergedFiles'][4:]:
        raw = files[row['file']]
        assert (extended_backup / 'sources' / row['file']).read_bytes() == raw
        assert row['sourceSha256'] == hashlib.sha256(raw).hexdigest().upper()
        values = raw.split(b'\n') if raw else []
        if raw.endswith(b'\n'):
            values.pop()
        assert len(values) == row['lineCount']
        if values:
            start = row['smallLine'] - 1
            assert new_small.split(b'\n')[start:start + len(values)] == [v.removesuffix(b'\r') for v in values]
        else:
            assert row['smallLine'] is None
    assert sorted(p.name for p in source.iterdir()) == ['one-hundred-lf.txt', 'one-hundred.txt', 'small.txt']
    subprocess.run(command, check=True, capture_output=True)
    records = [json.loads(line) for line in (report / 'journal.jsonl').read_text().splitlines()]
    small = next(row for row in records if row['file'] == 'small.txt')
    assert small['source']['lines'] == small['output']['lines'] == 107
    expected = b''.join(hashlib.sha1(value).hexdigest().upper().encode() + b'\n' for value in new_small.split(b'\n')[:-1])
    assert (report / 'files/small.txt.sha1').read_bytes() == expected
    try:
        module.consolidate(source, report, root / 'no-op-backup', Path(worker), True, 100)
        raise AssertionError('repeat must not merge small.txt into itself')
    except ValueError:
        pass
    assert not (root / 'no-op-backup').exists()
print('Inventory cleanup passed: legacy cleanup, exclusive 100-line cutoff, empty/blank/CRLF/unterminated records, existing aggregate extension, original-line mapping, duplicates, unscanned lists, rollback, backups, resumed hashing and safe repeat.')
