"""Exercise the real Docker stream path using a disposable RAM-only fixture."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from compact_index import Index

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).parents[1] / 'scripts/publish-compact-overlay.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
scripts = Path(__file__).parents[1].resolve() / 'scripts'
fixture = '''
import json,time
from pathlib import Path
from compact_index import build_index
p=Path('/work/fixture.pwnidx')
r=build_index(p,['fixture.txt'],[(bytes(20),0,19,2)],reserve=0)
r.update(state='verified',savedProvenanceVerified=True,originalOrderHashChecksumsVerified=True,originalLines=2)
Path(str(p)+'.receipt.json').write_text(json.dumps(r))
print('ready',flush=True)
time.sleep(600)
'''
container = subprocess.check_output([
    'docker', 'run', '-d', '--pull=never', '--network', 'none', '--memory', '128m', '--memory-swap', '128m',
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--tmpfs', '/work:rw,nosuid,nodev,noexec,size=16000000',
    '--mount', f'type=bind,src={scripts},dst=/app,readonly', '-w', '/app',
    'python:3.13-alpine', 'python3', '-c', fixture,
], text=True).strip()
try:
    # Bounded streaming wait; fixture contains no user inventory or secrets.
    ready = subprocess.Popen(['docker', 'logs', '-f', container], stdout=subprocess.PIPE, text=True)
    try:
        if ready.stdout.readline().strip() != 'ready':
            raise RuntimeError('fixture did not start')
    finally:
        ready.terminate()
        ready.wait(timeout=10)
        ready.stdout.close()
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / 'fixture.pwnidx'
        report = publisher.publish(Path('/work/fixture.pwnidx'), target, 0,
                                   lambda *args: (_ for _ in ()).throw(AssertionError('unexpected disk wait')),
                                   container=container)
        assert report['state'] == 'published'
        assert json.loads(Path(str(target) + '.receipt.json').read_text())['originalLines'] == 2
        index = Index(target)
        try:
            assert index.lookup(bytes(20)) == {'count': 2, 'files': [
                {'file': 'fixture.txt', 'count': 2, 'lineRanges': [[19, 20]]}]}
        finally:
            index.close()
    print('Docker RAM-to-disk stream, saved checksum and provenance passed.')
finally:
    # Only the exact newly created fixture container is removed.
    subprocess.run(['docker', 'rm', '-f', container], check=True, stdout=subprocess.DEVNULL)
