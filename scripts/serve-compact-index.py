"""Private, bounded prefix service. Never accepts passwords or complete hashes.

Wire format: <8sII> (PWNPRF01, catalog JSON bytes, 20-bit prefix),
UTF-8 catalog, then the index's existing uint32 raw-size + zlib block.
Clients decompress and match the remaining hash locally. Multiple disjoint
indexes use PWNPRF02: <8sII> (magic, frame count, prefix), followed by uint32
length + complete PWNPRF01 frame for each index. No blocks are recompressed.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import struct
import threading

from compact_index import Index, MAX_BLOCK

ENVELOPE = struct.Struct('<8sII')
CONTENT_TYPE = 'application/vnd.hanasand.pwned-prefix'
MAX_INDEXES = 16
MAX_RESPONSE = 32 * 1024 * 1024


class PrefixServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, path, overlays=()):
        if len(overlays) >= MAX_INDEXES:
            raise ValueError('too many indexes')
        self.indexes, self.catalogs = [], []
        self.slots = threading.BoundedSemaphore(2)
        try:
            files = set()
            for candidate in (path, *overlays):
                index = Index(candidate)
                self.indexes.append(index)
                for name in index.files:
                    if name in files:
                        raise ValueError('overlapping source filenames would double-count occurrences')
                    files.add(name)
                self.catalogs.append(json.dumps(index.files, separators=(',', ':')).encode())
            if sum(map(len, self.catalogs)) > 1024 * 1024:
                raise ValueError('file catalogs exceed response budget')
            self.index, self.catalog = self.indexes[0], self.catalogs[0]
            super().__init__(address, Handler)
        except BaseException:
            for index in self.indexes:
                index.close()
            raise

    def process_request(self, request, address):
        self.slots.acquire()
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def server_close(self):
        super().server_close()
        for index in self.indexes:
            index.close()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, *args):
        # Prefixes need not enter logs, even though they are not full hashes.
        pass

    def send_body(self, status, body, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            return self.send_body(200, b'{"ok":true}')
        match = re.fullmatch(r'/range/([0-9A-Fa-f]{5})', self.path)
        if not match:
            return self.send_body(400, b'{"error":"A five-character SHA-1 prefix is required."}')
        prefix = int(match[1], 16)
        try:
            frames, raw_total, wire_total = [], 0, 16
            for index, catalog in zip(self.server.indexes, self.server.catalogs):
                start, end = index.directory[prefix:prefix + 2]
                wire_total += 4 + 16 + len(catalog) + end - start
                if wire_total > MAX_RESPONSE:
                    raise ValueError('prefix response exceeds size budget')
                if end == start:
                    block = b''
                else:
                    if not 4 < end - start <= MAX_BLOCK + 65536:
                        raise ValueError('invalid block size')
                    block = os.pread(index.file.fileno(), end - start, start)
                    if len(block) != end - start:
                        raise ValueError('invalid saved block')
                    expected, = struct.unpack_from('<I', block)
                    raw_total += expected
                    if expected < 8 or raw_total > MAX_BLOCK:
                        raise ValueError('prefix expansion exceeds size budget')
                frames.append(ENVELOPE.pack(b'PWNPRF01', len(catalog), prefix) + catalog + block)
            body = frames[0] if len(frames) == 1 else (
                ENVELOPE.pack(b'PWNPRF02', len(frames), prefix)
                + b''.join(struct.pack('<I', len(frame)) + frame for frame in frames))
        except (OSError, ValueError, struct.error):
            return self.send_body(503, b'{"error":"Index unavailable."}')
        self.send_body(200, body, CONTENT_TYPE)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('index')
    parser.add_argument('--overlay', action='append', default=[], help='verified index with disjoint original filenames')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8099)
    args = parser.parse_args()
    with PrefixServer((args.host, args.port), args.index, args.overlay) as server:
        server.serve_forever()
