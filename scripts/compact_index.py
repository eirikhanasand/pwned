"""Compact SHA-1 lookup prototype with lossless file/line provenance.

Consumes records sorted by (20-byte SHA-1, file id, original line number).
One in-memory prefix directory points to compressed blocks in one disk file.
This module never deletes source data and is not yet the production builder.
"""
from array import array
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import zlib

MAGIC = b'PWNIDX01'
HEADER = struct.Struct('<8sQQ')  # catalog bytes, unique hashes
PREFIXES = 1 << 20
DIRECTORY_BYTES = (PREFIXES + 1) * 8
MAX_BLOCK = 64 * 1024 * 1024


def varint(value):
    if not 0 <= value < 1 << 64:
        raise ValueError('integer outside uint64 range')
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def read_varint(data, position, end):
    value = 0
    for shift in range(0, 70, 7):
        if position >= end:
            raise ValueError('truncated provenance')
        byte = data[position]
        position += 1
        if shift == 63 and byte > 1:
            raise ValueError('provenance integer overflow')
        value |= (byte & 127) << shift
        if byte < 128:
            return value, position
    raise ValueError('invalid provenance integer')


def prefix_of(digest):
    return int.from_bytes(digest[:3], 'big') >> 4


def encode_locations(locations):
    result = bytearray(varint(len(locations)))
    previous_file = 0
    for file_id, runs in locations:
        result += varint(file_id - previous_file)
        result += varint(len(runs))
        previous_line = 0
        for start, count in runs:
            result += varint(start - previous_line)
            result += varint(count)
            previous_line = start + count - 1
        previous_file = file_id
    return result


def build_index(path, files, records, reserve=150_000_000_000):
    """Build from an already sorted stream; return verification metadata.

    Each record is (digest, file_id, first_line, contiguous_line_count).
    Exclusive creation and cleanup leave existing indexes untouched on failure.
    """
    path = Path(path)
    catalog = json.dumps(files, ensure_ascii=False, separators=(',', ':')).encode()
    if len(catalog) > MAX_BLOCK or len(set(files)) != len(files):
        raise ValueError('invalid file catalog')
    if path.exists():
        raise FileExistsError(path)
    temporary = path.with_name(path.name + '.partial')
    directory = array('Q', [0]) * (PREFIXES + 1)
    directory_start = HEADER.size + len(catalog)
    unique = occurrences = next_prefix = 0
    current_prefix = None
    hashes, offsets, postings = bytearray(), array('I', [0]), bytearray()

    with temporary.open('xb') as output:
        try:
            def check_space(needed):
                if shutil.disk_usage(path.parent).free < reserve + needed:
                    raise RuntimeError('disk reserve reached; sources unchanged')

            check_space(directory_start + DIRECTORY_BYTES)
            output.write(HEADER.pack(MAGIC, len(catalog), 0))
            output.write(catalog)
            output.write(bytes(DIRECTORY_BYTES))

            def flush_bucket():
                nonlocal next_prefix, hashes, offsets, postings
                if current_prefix is None:
                    return
                while next_prefix <= current_prefix:
                    directory[next_prefix] = output.tell()
                    next_prefix += 1
                stored_offsets = array('I', offsets)
                if sys.byteorder != 'little':
                    stored_offsets.byteswap()
                raw = struct.pack('<I', len(hashes) // 18) + hashes + stored_offsets.tobytes() + postings
                if len(raw) > MAX_BLOCK:
                    raise RuntimeError('prefix block exceeds memory bound')
                encoded = struct.pack('<I', len(raw)) + zlib.compress(raw, level=1)
                # Verify compression round-trip before publishing the block.
                if zlib.decompress(encoded[4:]) != raw:
                    raise RuntimeError('block verification failed')
                check_space(len(encoded))
                output.write(encoded)
                hashes, offsets, postings = bytearray(), array('I', [0]), bytearray()

            def emit(digest, locations):
                nonlocal current_prefix, unique
                prefix = prefix_of(digest)
                if current_prefix != prefix:
                    flush_bucket()
                    current_prefix = prefix
                encoded = encode_locations(locations)
                if 8 + len(hashes) + 18 + (len(offsets) + 1) * 4 + len(postings) + len(encoded) > MAX_BLOCK:
                    raise RuntimeError('prefix block exceeds memory bound')
                hashes.extend(digest[2:])
                postings.extend(encoded)
                offsets.append(len(postings))
                unique += 1

            previous = None
            locations = []
            for digest, file_id, start, count in records:
                if not isinstance(digest, bytes) or len(digest) != 20 or not 0 <= file_id < len(files):
                    raise ValueError('invalid SHA-1 or source id')
                if not 1 <= start <= start + count - 1 < 1 << 64 or count <= 0:
                    raise ValueError('invalid source line range')
                key = (digest, file_id, start)
                if previous is not None and key <= previous:
                    raise ValueError('records must be strictly ordered')
                if previous is None or digest != previous[0]:
                    if previous is not None:
                        emit(previous[0], locations)
                    locations = []
                if not locations or locations[-1][0] != file_id:
                    locations.append((file_id, []))
                runs = locations[-1][1]
                if runs and start <= runs[-1][0] + runs[-1][1] - 1:
                    raise ValueError('overlapping source lines')
                if runs and start == runs[-1][0] + runs[-1][1]:
                    runs[-1][1] += count
                else:
                    runs.append([start, count])
                occurrences += count
                previous = key
            if previous is not None:
                emit(previous[0], locations)
            flush_bucket()
            while next_prefix <= PREFIXES:
                directory[next_prefix] = output.tell()
                next_prefix += 1
            end = output.tell()
            output.seek(0)
            output.write(HEADER.pack(MAGIC, len(catalog), unique))
            output.seek(directory_start)
            if sys.byteorder != 'little':
                directory.byteswap()
            output.write(directory.tobytes())
            output.flush()
            os.fsync(output.fileno())
            if output.seek(0, 2) != end:
                raise RuntimeError('index size mismatch')
            with temporary.open('rb') as saved:
                checksum = hashlib.file_digest(saved, 'sha256').hexdigest()
            os.link(temporary, path)  # Never overwrite an existing release.
            temporary.unlink()
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    return {'uniqueHashes': unique, 'occurrences': occurrences, 'bytes': end, 'sha256': checksum}


class Index:
    def __init__(self, path):
        self.file = open(path, 'rb')
        try:
            magic, catalog_size, self.unique = HEADER.unpack(self.file.read(HEADER.size))
            if magic != MAGIC or catalog_size > MAX_BLOCK:
                raise ValueError('invalid index header')
            self.files = json.loads(self.file.read(catalog_size))
            if not isinstance(self.files, list) or not all(isinstance(f, str) for f in self.files):
                raise ValueError('invalid file catalog')
            self.directory = array('Q')
            raw = self.file.read(DIRECTORY_BYTES)
            if len(raw) != DIRECTORY_BYTES:
                raise ValueError('truncated prefix directory')
            self.directory.frombytes(raw)
            if sys.byteorder != 'little':
                self.directory.byteswap()
            if self.directory[0] != HEADER.size + catalog_size + DIRECTORY_BYTES or self.directory[-1] != os.fstat(self.file.fileno()).st_size:
                raise ValueError('invalid index boundaries')
            if any(a > b for a, b in zip(self.directory, self.directory[1:])):
                raise ValueError('unordered prefix directory')
        except BaseException:
            self.file.close()
            raise

    def close(self):
        self.file.close()

    def records(self):
        """Read every saved hash and provenance run, validating block structure.

        Used for full verification of new overlays, not on the request path.
        Yields the same (digest, file_id, first_line, count) shape as build_index.
        """
        unique = 0
        for prefix in range(PREFIXES):
            start, end = self.directory[prefix:prefix + 2]
            if start == end:
                continue
            if not 4 < end - start <= MAX_BLOCK + 65536:
                raise ValueError('invalid compressed block size')
            block = os.pread(self.file.fileno(), end - start, start)
            if len(block) != end - start:
                raise ValueError('truncated compressed block')
            expected, = struct.unpack_from('<I', block)
            if not 8 <= expected <= MAX_BLOCK:
                raise ValueError('invalid raw block size')
            inflater = zlib.decompressobj()
            data = inflater.decompress(block[4:], MAX_BLOCK + 1)
            if len(data) != expected or not inflater.eof or inflater.unused_data:
                raise ValueError('corrupt compressed block')
            count, = struct.unpack_from('<I', data)
            offsets_start = 4 + count * 18
            postings_start = offsets_start + (count + 1) * 4
            if not count or postings_start > len(data):
                raise ValueError('invalid block count')
            offsets = struct.unpack_from(f'<{count + 1}I', data, offsets_start)
            if offsets[0] != 0 or postings_start + offsets[-1] != len(data):
                raise ValueError('invalid provenance boundaries')
            previous_digest = None
            for i in range(count):
                suffix = data[4 + i * 18:4 + (i + 1) * 18]
                digest = (prefix >> 4).to_bytes(2, 'big') + suffix
                if prefix_of(digest) != prefix or (previous_digest is not None and digest <= previous_digest):
                    raise ValueError('unordered or misplaced hash')
                previous_digest = digest
                position, limit = postings_start + offsets[i], postings_start + offsets[i + 1]
                if not postings_start <= position < limit <= len(data):
                    raise ValueError('invalid provenance offsets')
                groups, position = read_varint(data, position, limit)
                if not 1 <= groups <= len(self.files):
                    raise ValueError('invalid provenance groups')
                file_id = 0
                for group in range(groups):
                    delta, position = read_varint(data, position, limit)
                    file_id += delta
                    if file_id >= len(self.files) or (group and not delta):
                        raise ValueError('invalid provenance source')
                    runs, position = read_varint(data, position, limit)
                    if not 1 <= runs <= (limit - position) // 2:
                        raise ValueError('invalid provenance runs')
                    line = 0
                    for _ in range(runs):
                        delta, position = read_varint(data, position, limit)
                        length, position = read_varint(data, position, limit)
                        if not delta or not length or line + delta + length - 1 >= 1 << 64:
                            raise ValueError('invalid provenance range')
                        line += delta
                        yield digest, file_id, line, length
                        line += length - 1
                if position != limit:
                    raise ValueError('trailing provenance data')
                unique += 1
        if unique != self.unique:
            raise ValueError('unique hash count mismatch')

    def lookup(self, digest):
        if len(digest) != 20:
            raise ValueError('SHA-1 must be exactly 20 bytes')
        prefix = prefix_of(digest)
        start, end = self.directory[prefix:prefix + 2]
        if start == end:
            return None
        if not 4 < end - start <= MAX_BLOCK + 65536:
            raise ValueError('invalid compressed block size')
        block = os.pread(self.file.fileno(), end - start, start)
        expected, = struct.unpack_from('<I', block)
        if expected > MAX_BLOCK:
            raise ValueError('oversized block')
        inflater = zlib.decompressobj()
        data = inflater.decompress(block[4:], MAX_BLOCK + 1)
        if len(data) != expected or not inflater.eof or inflater.unused_data:
            raise ValueError('corrupt compressed block')
        count, = struct.unpack_from('<I', data)
        offsets_start = 4 + count * 18
        postings_start = offsets_start + (count + 1) * 4
        if postings_start > len(data):
            raise ValueError('truncated block')
        suffix = digest[2:]
        low, high = 0, count
        while low < high:
            mid = (low + high) // 2
            candidate = data[4 + mid * 18:4 + (mid + 1) * 18]
            if candidate < suffix:
                low = mid + 1
            else:
                high = mid
        if low == count or data[4 + low * 18:4 + (low + 1) * 18] != suffix:
            return None
        first, last = struct.unpack_from('<II', data, offsets_start + low * 4)
        position, limit = postings_start + first, postings_start + last
        if not postings_start <= position < limit <= len(data):
            raise ValueError('invalid provenance bounds')
        groups, position = read_varint(data, position, limit)
        results = []
        file_id = total = 0
        for _ in range(groups):
            delta, position = read_varint(data, position, limit)
            file_id += delta
            if file_id >= len(self.files):
                raise ValueError('invalid provenance source')
            runs, position = read_varint(data, position, limit)
            ranges = []
            line = matches = 0
            for _ in range(runs):
                delta, position = read_varint(data, position, limit)
                length, position = read_varint(data, position, limit)
                if not delta or not length:
                    raise ValueError('invalid provenance range')
                line += delta
                ranges.append([line, line + length - 1])
                line += length - 1
                matches += length
            total += matches
            results.append({'file': self.files[file_id], 'count': matches, 'lineRanges': ranges})
        if position != limit:
            raise ValueError('trailing provenance data')
        return {'count': total, 'files': results}
