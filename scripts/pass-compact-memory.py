"""Short-lived Linux helper: pass ONLY a validated, read-only donor memory fd.

Run in the donor's PID namespace as root with SYS_PTRACE and DAC_OVERRIDE.
The receiver stays unprivileged inside the original memory-limited container.
"""
import array
import os
from pathlib import Path
import socket
import sys

socket_path, start, base, length = sys.argv[1:]
start, base, length = int(start), int(base), int(length)
fields = Path('/proc/1/stat').read_text().rsplit(')', 1)[1].split()
if fields[0] != 'T' or int(fields[19]) != start:
    raise RuntimeError('donor is not the expected stopped process')
if length <= 0:
    raise ValueError('invalid mapping length')
for mapping in Path('/proc/1/maps').read_text().splitlines():
    parts = mapping.split()
    lo, hi = (int(x, 16) for x in parts[0].split('-'))
    if lo == base and hi >= base + length and parts[1] == 'rw-p' and len(parts) == 5:
        break
else:
    raise RuntimeError('expected anonymous record mapping not found')
with socket.socket(socket.AF_UNIX) as connection:
    connection.connect(socket_path)
    fd = os.open('/proc/1/mem', os.O_RDONLY | os.O_CLOEXEC)
    try:
        if len(os.pread(fd, 25, base)) != 25 or len(os.pread(fd, 25, base + length - 25)) != 25:
            raise RuntimeError('record mapping not readable')
        connection.sendmsg([b'M'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
    finally:
        os.close(fd)
print('Read-only donor memory descriptor delivered; helper exiting.')
