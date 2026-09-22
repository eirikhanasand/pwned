"""Private, bounded prefix service. Never accepts passwords or complete hashes.

Wire format: <8sII> (PWNPRF01, catalog JSON bytes, 20-bit prefix),
UTF-8 catalog, then a uint32 raw-size + zlib block.
Clients decompress and match the remaining hash locally. Source indexes are
merged into one canonical PWNPRF01 frame: one occurrence per hash/file, with
unsorted originals preferred over matching sorted copies. Saved audit data
is read-only; normalization applies to every hash in the requested prefix.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import struct
import threading
import zlib

from compact_index import Index
from deduplicated_prefix import canonical_block

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
            self.index = self.indexes[0]
            names = [name for index in self.indexes for name in index.files]
            file_ids = {name: fid for fid, name in enumerate(names)}
            self.originals = {fid: file_ids[name[:-11] + '.txt']
                              for fid, name in enumerate(names)
                              if name.endswith('_sorted.txt') and name[:-11] + '.txt' in file_ids}
            self.catalog = json.dumps(names, separators=(',', ':')).encode()
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
            block = canonical_block(self.server.indexes, prefix, self.server.originals)
            catalog = self.server.catalog
            if 16 + len(catalog) + len(block) > MAX_RESPONSE:
                raise ValueError('prefix response exceeds size budget')
            body = ENVELOPE.pack(b'PWNPRF01', len(catalog), prefix) + catalog + block
        except (OSError, ValueError, struct.error, zlib.error):
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
