"""Audited one-off handoff of the already hashed/sorted Inspur master inventory.

No command kills, resumes or restarts the donor. It remains the RAM holder.
Early source deletion is separately gated on verified reuse and durable new writes.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

CONTAINER = 'pwned-compact-master-25a24d9'
ROOT = Path('/home/hanasand/pwned/compact-inventory')
SOURCE = Path('/home/hanasand/pwned/passwords/all_in_one/all_in_one_sorted.txt')
RECEIPT = ROOT/'master.pwnidx.handoff.json'
LINES, SIZE = 26921656388, 305105563518
SHA = 'f83a01a3d1c057473b36de871d65546d060c81a31e1e658203c299e7e34c2dfe'

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()

def persist(path, data, exclusive=False):
    temporary = path if exclusive else path.with_name(path.name+'.new')
    with temporary.open('x' if exclusive else 'w') as output:
        json.dump(data, output, indent=2); output.write('\n')
        output.flush(); os.fsync(output.fileno())
    if not exclusive: temporary.replace(path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    os.fsync(fd); os.close(fd)

def snapshot(st):
    return {k: getattr(st,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')}

def donor():
    inspection=json.loads(run('docker','inspect',CONTAINER))[0]
    if not inspection['State']['Running'] or inspection['State']['OOMKilled']:
        raise RuntimeError('donor not alive and healthy')
    if inspection['HostConfig']['Memory']!=800000000000 or inspection['HostConfig']['MemorySwap']!=800000000000:
        raise RuntimeError('donor memory/swap limits changed')
    expected_command=['/worker','/source/master.txt','/output/master.pwnidx','all_in_one/all_in_one_sorted.txt',str(LINES),str(LINES),str(SIZE),SHA,'800000000000','150000000000','16']
    if inspection['Config']['Cmd']!=expected_command:
        raise RuntimeError('donor was not launched with the verified master profile')
    mounts={item['Destination']:item for item in inspection['Mounts']}
    if mounts.get('/source/master.txt',{}).get('Source')!=str(SOURCE) or mounts['/source/master.txt']['RW'] or mounts.get('/output',{}).get('Source')!=str(ROOT):
        raise RuntimeError('donor source/output mounts differ from the expected inventory')
    info=json.loads(run('docker','exec',CONTAINER,'python','-c',
        "import json;from pathlib import Path;f=Path('/proc/1/stat').read_text().rsplit(')',1)[1].split();print(json.dumps({'state':f[0],'start':int(f[19]),'maps':Path('/proc/1/maps').read_text(),'swapMax':Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),'memoryMax':Path('/sys/fs/cgroup/memory.max').read_text().strip()}))"))
    if info['swapMax']!='0' or info['memoryMax']!='800000000000':
        raise RuntimeError('effective memory/no-swap limits do not match Docker configuration')
    return inspection,info

def check_identity(receipt):
    inspection,info=donor()
    if inspection['Id']!=receipt['containerId'] or info['start']!=receipt['donorStart'] or info['state']!='T':
        raise RuntimeError('donor identity/state changed; do not touch source')
    return inspection,info

if sys.argv[1:] == ['start']:
    if RECEIPT.exists(): raise RuntimeError('handoff receipt already exists; inspect before any retry')
    report=json.loads((ROOT/'master.pwnidx.status.json').read_text())
    if report['state']!='writing' or report['hashedLines']!=LINES or report['hashedNewlines']!=LINES or report['readBytes']!=SIZE or report['recordMemoryBytes']!=LINES*25:
        raise RuntimeError('donor has not completed expected hashing/sorting checks')
    source=SOURCE.lstat()
    if not stat.S_ISREG(source.st_mode) or source.st_size!=SIZE or source.st_nlink!=1:
        raise RuntimeError('unexpected original source')
    for name in ('compact-resume','pass-compact-memory.py','run-compact-resume.py'):
        if not (ROOT/name).is_file(): raise RuntimeError('missing receiver artifact: '+name)
    inspection,info=donor()
    mappings=[]
    for line in info['maps'].splitlines():
        fields=line.split(); lo,hi=(int(x,16) for x in fields[0].split('-'))
        if len(fields)==5 and fields[1]=='rw-p' and hi-lo==((LINES*25+4095)//4096)*4096: mappings.append(lo)
    if len(mappings)!=1: raise RuntimeError('cannot uniquely identify packed record mapping')
    receipt={'state':'preparing','createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'container':CONTAINER,'containerId':inspection['Id'],'donorStart':info['start'],'recordBase':mappings[0],
        'source':str(SOURCE),'sourceSnapshot':snapshot(source),'sourceSha256':SHA,'expectedLines':LINES,
        'sourceDeleted':False,'memoryLimitBytes':800000000000,'diskReserveBytes':100000000000,
        'reserveReason':'Reclaiming the original leaves about 120 GB at projected completion; retain a 100 GB floor.',
        'risk':'Original early deletion was user-authorized. Host/donor loss before durable completion requires external backup.',
        'receiverSha256':hashlib.sha256((ROOT/'compact-resume').read_bytes()).hexdigest(),
        'receiverCommand':['/output/compact-resume','/source/master.txt','/output/master.pwnidx','all_in_one/all_in_one_sorted.txt',
          str(LINES),str(LINES),str(SIZE),SHA,'800000000000','100000000000','16','/output/master.memory.sock',str(mappings[0]),str(info['start'])]}
    persist(RECEIPT,receipt,exclusive=True)
    run('docker','kill','--signal','STOP',CONTAINER)
    for attempt in range(50):
        _,info=donor()
        if info['state']=='T': break
        time.sleep(.1)
    check_identity(receipt)
    receipt['frozenStatus']=json.loads((ROOT/'master.pwnidx.status.json').read_text())
    receipt['frozenPartialBytes']=(ROOT/'master.pwnidx.partial').stat().st_size
    receipt['state']='donor_stopped'; persist(RECEIPT,receipt)
    run('docker','exec','-d','--user','1000:1000',CONTAINER,'python','/output/run-compact-resume.py','/output/master.pwnidx.handoff.json')
    for attempt in range(100):
        socket_path=ROOT/'master.memory.sock'
        if socket_path.exists(): break
        time.sleep(.1)
    else: raise RuntimeError('receiver socket missing; donor remains safely stopped')
    run('docker','run','--rm','--pid','container:'+CONTAINER,'--memory','64m','--memory-swap','64m','--network','none',
        '--read-only','--cap-drop','ALL','--cap-add','SYS_PTRACE','--cap-add','DAC_OVERRIDE',
        '-v',str(ROOT)+':/output','-v',str(ROOT/'pass-compact-memory.py')+':/helper.py:ro',
        'python:3.13-alpine','python','/helper.py','/output/master.memory.sock',str(info['start']),str(mappings[0]),str(LINES*25))
    receipt['state']='checking_existing_blocks'; persist(RECEIPT,receipt)
    print(json.dumps({'state':receipt['state'],'frozenPartialBytes':receipt['frozenPartialBytes'],'sourceDeleted':False}))
elif sys.argv[1:] == ['release-source','--allow-early-source-delete']:
    receipt=json.loads(RECEIPT.read_text()); check_identity(receipt)
    if receipt['sourceDeleted']: raise RuntimeError('source already released')
    report=json.loads((ROOT/'master.pwnidx.handoff.status.json').read_text())
    if report['state']!='writing' or report['reusedBytes']<receipt['frozenStatus']['writtenBytes'] or report['writtenBytes']<receipt['frozenPartialBytes']+(512<<20):
        raise RuntimeError('all old blocks and 512 MiB of new output must be checked/written before release')
    if report.get('rehashPerformed') is not False or report.get('resortPerformed') is not False:
        raise RuntimeError('unexpected receiver mode')
    if (ROOT/'master.pwnidx.handoff.exit.json').exists(): raise RuntimeError('receiver exited; inspect before release')
    fd=os.open(SOURCE,os.O_RDWR|os.O_NOFOLLOW)
    try:
        if snapshot(os.fstat(fd))!=receipt['sourceSnapshot'] or snapshot(SOURCE.lstat())!=receipt['sourceSnapshot']:
            raise RuntimeError('original source identity changed')
        # Flush the receiver's append-only output before reclaiming the input.
        output_fd=os.open(ROOT/'master.pwnidx.partial',os.O_RDWR|os.O_NOFOLLOW)
        os.fsync(output_fd); os.close(output_fd)
        receipt['state']='source_release_intent'; receipt['releaseChecks']=report
        persist(RECEIPT,receipt)
        # Unlink alone cannot reclaim blocks: the stopped donor holds an fd/bind mount.
        os.ftruncate(fd,0); os.fsync(fd); SOURCE.unlink()
        directory_fd=os.open(SOURCE.parent,os.O_RDONLY|os.O_DIRECTORY)
        os.fsync(directory_fd); os.close(directory_fd)
        receipt['sourceDeleted']=True; receipt['sourceBytesReleased']=SIZE; receipt['state']='writing_without_original'
        receipt['sourceReleasedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        persist(RECEIPT,receipt)
    finally: os.close(fd)
    print(json.dumps({'state':receipt['state'],'sourceBytesReleased':SIZE,'sourceDeleted':True}))
else:
    raise SystemExit('usage: handoff-master-inventory.py start | release-source --allow-early-source-delete')
