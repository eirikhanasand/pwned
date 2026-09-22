"""Canonical lookup view over immutable file/line provenance.

Keep one occurrence per hash/source and prefer an unsorted source only when
that same hash is present there. Original line numbers remain audit references.
"""
from array import array
import heapq
import os
import struct
import sys
import zlib

from compact_index import MAX_BLOCK, encode_locations, read_varint


def read_block(index, prefix, budget=MAX_BLOCK + 65536):
    start, end = index.directory[prefix:prefix + 2]
    if start == end:
        return b''
    if not 4 < end - start <= min(MAX_BLOCK + 65536, budget):
        raise ValueError('invalid block size')
    block = os.pread(index.file.fileno(), end - start, start)
    if len(block) != end - start:
        raise ValueError('truncated block')
    expected, = struct.unpack_from('<I', block)
    if not 8 <= expected <= MAX_BLOCK:
        raise ValueError('invalid raw block size')
    return block


def first_locations(block, prefix, file_base, file_count):
    if not block:
        return
    expected, = struct.unpack_from('<I', block)
    inflater = zlib.decompressobj()
    raw = inflater.decompress(block[4:], expected + 1)
    if len(raw) != expected or not inflater.eof or inflater.unused_data:
        raise ValueError('corrupt compressed block')
    count, = struct.unpack_from('<I', raw)
    offsets = 4 + count * 18
    postings = offsets + (count + 1) * 4
    if not count or postings > len(raw):
        raise ValueError('invalid block count')
    if struct.unpack_from('<I', raw, offsets)[0] != 0:
        raise ValueError('invalid first offset')
    previous = None
    last = 0
    for entry in range(count):
        suffix = raw[4 + entry * 18:22 + entry * 18]
        if suffix[0] >> 4 != prefix & 15 or (previous is not None and suffix <= previous):
            raise ValueError('unordered or misplaced hash')
        previous = suffix
        first, last = struct.unpack_from('<II', raw, offsets + entry * 4)
        position, end = postings + first, postings + last
        if not postings <= position < end <= len(raw):
            raise ValueError('invalid provenance offsets')
        groups, position = read_varint(raw, position, end)
        if not 1 <= groups <= file_count:
            raise ValueError('invalid provenance groups')
        locations = []
        file_id = 0
        for group in range(groups):
            delta, position = read_varint(raw, position, end)
            file_id += delta
            if file_id >= file_count or (group and not delta):
                raise ValueError('invalid provenance source')
            runs, position = read_varint(raw, position, end)
            if not 1 <= runs <= (end - position) // 2:
                raise ValueError('invalid provenance runs')
            line = first_line = 0
            for run in range(runs):
                step, position = read_varint(raw, position, end)
                length, position = read_varint(raw, position, end)
                if not step or not length:
                    raise ValueError('invalid provenance run')
                if run == 0:
                    first_line = step
                line += step + length - 1
                if line > (1 << 53) - 1:
                    raise ValueError('unsafe line number')
            locations.append((file_base + file_id, first_line))
        if position != end:
            raise ValueError('trailing provenance bytes')
        yield suffix, locations
    if postings + last != len(raw):
        raise ValueError('trailing block bytes')


def canonical_block(indexes, prefix, originals):
    blocks, compressed, expanded = [], 0, 0
    for index in indexes:
        block = read_block(index, prefix, 32 * 1024 * 1024 - compressed)
        compressed += len(block)
        expanded += struct.unpack_from('<I', block)[0] if block else 0
        if expanded > MAX_BLOCK:
            raise ValueError('prefix expansion exceeds size budget')
        blocks.append(block)
    streams, base = [], 0
    for index, block in zip(indexes, blocks):
        streams.append(first_locations(block, prefix, base, len(index.files)))
        base += len(index.files)
    hashes, offsets, postings = bytearray(), array('I', [0]), bytearray()

    def emit(suffix, locations):
        retained = [(fid, [(line, 1)]) for fid, line in sorted(locations.items())
                    if originals.get(fid) not in locations]
        encoded = encode_locations(retained)
        if 8 + len(hashes) + 18 + len(offsets) * 4 + len(postings) + len(encoded) > MAX_BLOCK:
            raise ValueError('canonical prefix exceeds size budget')
        hashes.extend(suffix)
        postings.extend(encoded)
        offsets.append(len(postings))

    previous, locations = None, {}
    for suffix, found in heapq.merge(*streams, key=lambda item: item[0]):
        if previous is not None and suffix != previous:
            emit(previous, locations)
            locations = {}
        previous = suffix
        for fid, line in found:
            locations[fid] = min(locations.get(fid, line), line)
    if previous is None:
        return b''
    emit(previous, locations)
    if sys.byteorder != 'little':
        offsets.byteswap()
    raw_size = 4 + len(hashes) + len(offsets) * 4 + len(postings)
    compressor = zlib.compressobj(level=1)
    compressed = [compressor.compress(part) for part in
                  (struct.pack('<I', len(hashes) // 18), hashes, offsets.tobytes(), postings)]
    compressed.append(compressor.flush())
    return struct.pack('<I', raw_size) + b''.join(compressed)
