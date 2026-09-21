"""End-to-end Docker handoff against a real stopped native builder (Linux).

Arguments: absolute test directory containing donor, receiver and helper.py.
Never targets production containers or data. Leaves failures available to inspect.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import zlib

root = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location('compact', Path(__file__).parents[1] / 'scripts/compact_index.py')
compact = importlib.util.module_from_spec(spec); spec.loader.exec_module(compact)

def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()

def status(path, wanted, timeout=180):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if path.exists():
            report = json.loads(path.read_text())
            if report['state'] in wanted: return report
            if report['state'] == 'failed': raise AssertionError(report)
        time.sleep(.1)
    raise TimeoutError((str(path), wanted))

for mode in (sys.argv[2:] or ('intact', 'partial-tail', 'corrupt', 'disk-wait', 'dense', 'receiver-restart')):
    folder = root / mode; folder.mkdir()
    os.chmod(folder, 0o777)
    data = b'\n'.join([b'duplicate', b'duplicate', b'', b'\x00\xff', b'crlf\r'] + [str(i).encode() for i in range(120000)]) + b'\n'
    (folder/'source').write_bytes(data)
    output = folder/'index'; catalog='fixtures/source.txt'
    header_size=24+len('["fixtures/source.txt"]')+(2**20+1)*8
    space=header_size+(2000000 if mode=='dense' else 300000)+10000000
    (folder/'space').write_text(str(space))
    for name in ('source','space'): os.chmod(folder/name,0o666)
    name=f'compact-handoff-test-{os.getpid()}-{mode}'
    args=['/source','/output/index',catalog,str(data.count(b'\n')),str(data.count(b'\n')),str(len(data)),hashlib.sha256(data).hexdigest(),str(5*1024**3),'10000000','2']
    command('docker','run','-d','--name',name,'--user','1000:1000','--memory','1g','--memory-swap','1g','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '-e','PWNED_TEST_SPACE_FILE=/output/space',*(['-e','PWNED_FIXTURE_DENSE=1'] if mode=='dense' else []),'-v',f'{folder}:/output','-v',f'{folder}/source:/source:ro','-v',f'{root}/donor:/donor:ro','-v',f'{root}/receiver:/receiver:ro',
            'python:3.13-alpine','/donor',*args)
    try:
        initial=status(Path(str(output)+'.status.json'),{'waiting_for_disk'})
        assert initial['hashedLines']==data.count(b'\n') and initial['writtenBytes']>header_size
        command('docker','kill','--signal','STOP',name)
        start=command('docker','exec',name,'python','-c',"from pathlib import Path;print(Path('/proc/1/stat').read_text().rsplit(')',1)[1].split()[19])")
        base=json.loads(Path(str(output)+'.donor.json').read_text())['base']
        partial=Path(str(output)+'.partial')
        before=partial.read_bytes()
        if mode=='partial-tail':
            with partial.open('r+b') as f: f.truncate(len(before)-9)
            before=partial.read_bytes()
        if mode=='corrupt':
            with partial.open('r+b') as f: f.seek(header_size+8); b=f.read(1); f.seek(-1,1); f.write(bytes([b[0]^0xff]))
        if mode not in ('disk-wait','receiver-restart'): (folder/'space').write_text(str(10**12))
        # Prove original content is never consulted by the replacement.
        (folder/'source').write_bytes(b'')
        command('docker','exec','-d',name,'/receiver',*args,'/output/memory.sock',str(base),start)
        status(Path(str(output)+'.handoff.status.json'),{'awaiting_memory'})
        command('docker','run','--rm','--pid',f'container:{name}','--memory','64m','--memory-swap','64m','--network','none','--read-only','--cap-drop','ALL','--cap-add','SYS_PTRACE','--cap-add','DAC_OVERRIDE',
                '-v',f'{folder}:/output','-v',f'{root}/helper.py:/helper.py:ro','python:3.13-alpine','python','/helper.py','/output/memory.sock',start,str(base),str(data.count(b'\n')*25))
        if mode=='corrupt':
            report=status(Path(str(output)+'.handoff.status.json'),{'failed'})
            assert not output.exists() and partial.exists()
            print(mode,'correctly rejected corruption',flush=True)
            continue
        if mode in ('disk-wait','receiver-restart'):
            status(Path(str(output)+'.handoff.status.json'),{'waiting_for_disk'})
            if mode=='receiver-restart':
                command('docker','exec',name,'python','-c',"import os,signal;from pathlib import Path\nfor p in Path('/proc').iterdir():\n if p.name.isdigit() and (p/'cmdline').read_bytes().split(b'\\0')[0]==b'/receiver':os.kill(int(p.name),signal.SIGKILL)")
                command('docker','exec','-d',name,'/receiver',*args,'/output/memory.sock',str(base),start)
                status(Path(str(output)+'.handoff.status.json'),{'awaiting_memory'})
                command('docker','run','--rm','--pid',f'container:{name}','--memory','64m','--memory-swap','64m','--network','none','--read-only','--cap-drop','ALL','--cap-add','SYS_PTRACE','--cap-add','DAC_OVERRIDE',
                        '-v',f'{folder}:/output','-v',f'{root}/helper.py:/helper.py:ro','python:3.13-alpine','python','/helper.py','/output/memory.sock',start,str(base),str(data.count(b'\n')*25))
            (folder/'space').write_text(str(10**12))
        report=status(Path(str(output)+'.handoff.status.json'),{'complete'})
        assert report['reusedBytes']>header_size and report['reusedLines']>0
        assert not report['rehashPerformed'] and not report['resortPerformed']
        assert report['verifiedLines']==data.count(b'\n') and report['savedProvenanceVerified']
        assert report['indexSha256']==hashlib.sha256(output.read_bytes()).hexdigest()
        assert output.read_bytes()[header_size:report['reusedBytes']]==before[header_size:report['reusedBytes']]
        expected={}
        for line,value in enumerate(data.split(b'\n')[:-1],1):
            value=value[:-1] if value.endswith(b'\r') else value
            digest=hashlib.sha1(value).digest()
            if mode=='dense' and line<=60000: digest=b'\0\0'+bytes([digest[2]&15])+digest[3:]
            expected.setdefault(digest,[]).append(line)
        index=compact.Index(output)
        assert index.unique==len(expected)
        # Exhaustive validation, decoding dense buckets once rather than 60,000 times.
        samples=list(expected.items())[:8]
        for prefix in range(2**20):
            lo,hi=index.directory[prefix:prefix+2]
            if lo==hi: continue
            encoded=os.pread(index.file.fileno(),hi-lo,lo)
            raw=zlib.decompress(encoded[4:]); count,=struct.unpack_from('<I',raw)
            posts=4+count*18+(count+1)*4
            for entry in range(count):
                digest=(prefix>>4).to_bytes(2,'big')+raw[4+entry*18:4+(entry+1)*18]
                a,b=struct.unpack_from('<II',raw,4+count*18+entry*4)
                position,limit=posts+a,posts+b
                groups,position=compact.read_varint(raw,position,limit)
                file_id,position=compact.read_varint(raw,position,limit)
                runs,position=compact.read_varint(raw,position,limit)
                assert groups==1 and file_id==0
                line=0; actual=[]
                for _ in range(runs):
                    delta,position=compact.read_varint(raw,position,limit)
                    length,position=compact.read_varint(raw,position,limit)
                    line+=delta; actual.extend(range(line,line+length)); line+=length-1
                assert position==limit and actual==expected.pop(digest)
        assert not expected
        for digest,lines in samples:
            result=index.lookup(digest)
            assert result['count']==len(lines) and result['files'][0]['file']==catalog
            assert [n for lo,hi in result['files'][0]['lineRanges'] for n in range(lo,hi+1)]==lines
        index.close()
        if mode=='partial-tail': assert report['discardedIncompleteTailBytes']>0
        print(mode,'passed: every hash/line/count, existing bytes preserved, no original needed',flush=True)
    finally:
        # Synthetic donor only; test scope is explicitly named above.
        command('docker','rm','-f',name)
print('All real-process handoff tests passed.',flush=True)
