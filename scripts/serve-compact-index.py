"""Private, bounded prefix service. Never accepts passwords or complete hashes.

Wire format: <8sII> (PWNPRF01, catalog JSON bytes, 20-bit prefix),
UTF-8 catalog, then the index's existing uint32 raw-size + zlib block.
Clients decompress and match the remaining hash locally.
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


class PrefixServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, path):
        self.index = Index(path)
        self.catalog = json.dumps(self.index.files, separators=(',', ':')).encode()
        self.slots = threading.BoundedSemaphore(2)
        try:
            super().__init__(address, Handler)
        except BaseException:
            self.index.close()
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
        self.index.close()


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
        index = self.server.index
        try:
            start, end = index.directory[prefix:prefix + 2]
            if end == start:
                block = b''
            else:
                if not 4 < end - start <= MAX_BLOCK + 65536:
                    raise ValueError('invalid block size')
                block = os.pread(index.file.fileno(), end - start, start)
                if len(block) != end - start or struct.unpack_from('<I', block)[0] > MAX_BLOCK:
                    raise ValueError('invalid saved block')
            body = ENVELOPE.pack(b'PWNPRF01', len(self.server.catalog), prefix) + self.server.catalog + block
        except (OSError, ValueError, struct.error):
            return self.send_body(503, b'{"error":"Index unavailable."}')
        self.send_body(200, body, CONTENT_TYPE)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('index')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8099)
    args = parser.parse_args()
    with PrefixServer((args.host, args.port), args.index) as server:
        server.serve_forever()
