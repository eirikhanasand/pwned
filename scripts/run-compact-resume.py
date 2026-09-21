"""Unprivileged receiver supervisor, run inside the donor's existing cgroup."""
import json
import os
from pathlib import Path
import subprocess
import sys

receipt = json.loads(Path(sys.argv[1]).read_text())
with open('/output/master.pwnidx.handoff.log', 'ab', buffering=0) as log:
    result = subprocess.run(receipt['receiverCommand'], stdout=log, stderr=subprocess.STDOUT)
    os.fsync(log.fileno())
path = Path('/output/master.pwnidx.handoff.exit.json')
with path.open('x') as output:
    json.dump({'exitCode': result.returncode}, output)
    output.flush(); os.fsync(output.fileno())
fd = os.open('/output', os.O_RDONLY | os.O_DIRECTORY)
os.fsync(fd); os.close(fd)
sys.exit(result.returncode)
