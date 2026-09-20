import importlib.util
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
    assert len(plan['files']) == 4
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
print('Inventory cleanup passed: username removal, mixed-list/fixture preservation, duplicate-preserving merge, unscanned single entries, backups, partial recovery, resumed line verification and overwrite refusal.')
