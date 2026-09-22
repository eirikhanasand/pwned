import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from compact_index import Index, build_index, prefix_of
from deduplicated_prefix import canonical_block, first_locations, read_block

spec = importlib.util.spec_from_file_location('service', Path(__file__).parents[1] / 'scripts/serve-compact-index.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)

A = bytes.fromhex('ABCDE' + '0' * 35)
B = bytes.fromhex('ABCDE' + '0' * 34 + '1')
C = bytes.fromhex('ABCDE' + '0' * 34 + '2')


class DeduplicatedPrefixTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.serial = 0

    def index(self, files, records):
        self.serial += 1
        path = self.root / str(self.serial)
        build_index(path, files, sorted(records), reserve=0)
        index = Index(path)
        self.addCleanup(index.close)
        return index

    def test_duplicates_adjacent_and_separate_keep_first_original_line(self):
        source = self.index(['Dutch.txt'], [(A, 0, 4640, 1), (A, 0, 1839686, 2), (B, 0, 20, 5)])
        expected = self.index(source.files, [(A, 0, 4640, 1), (B, 0, 20, 1)])
        self.assertEqual(canonical_block([source], prefix_of(A), {}), read_block(expected, prefix_of(A)))
        self.assertEqual(source.lookup(A)['count'], 3)  # Immutable source provenance is preserved.

    def test_sorted_original_preference_is_per_hash_across_indexes(self):
        sorted_index = self.index(['Dutch_sorted.txt', 'all_in_one_sorted.txt'],
                                  [(A, 0, 3717822, 2), (B, 0, 90, 1), (A, 1, 12010103436, 1)])
        original = self.index(['Dutch.txt', 'unrelated.txt'],
                              [(A, 0, 4640, 1), (A, 0, 1839686, 1), (C, 0, 44, 1), (A, 1, 2, 1)])
        expected = self.index(sorted_index.files + original.files,
                              [(A, 1, 12010103436, 1), (A, 2, 4640, 1), (A, 3, 2, 1),
                               (B, 0, 90, 1), (C, 2, 44, 1)])
        with service.PrefixServer(('127.0.0.1', 0), sorted_index.file.name, [original.file.name]) as server:
            self.assertEqual(server.originals, {0: 2})
            self.assertEqual(canonical_block(server.indexes, prefix_of(A), server.originals),
                             read_block(expected, prefix_of(A)))

    def test_same_directory_and_exact_basename_only(self):
        files = ['a/name_sorted.txt', 'b/name.txt', 'a/name.txt', 'a/name_sorted_2.txt']
        source = self.index(files, [(A, fid, 10 + fid, 1) for fid in range(4)])
        expected = self.index(files, [(A, fid, 10 + fid, 1) for fid in (1, 2, 3)])
        with service.PrefixServer(('127.0.0.1', 0), source.file.name) as server:
            self.assertEqual(server.originals, {0: 2})
            self.assertEqual(canonical_block(server.indexes, prefix_of(A), server.originals),
                             read_block(expected, prefix_of(A)))

    def test_no_matches_and_malformed_blocks(self):
        source = self.index(['one.txt'], [(A, 0, 5, 1)])
        self.assertEqual(canonical_block([source], prefix_of(A) + 1, {}), b'')
        block = read_block(source, prefix_of(A))
        for bad in (block[:-1], block + b'junk', struct.pack('<I', 8) + block[4:]):
            with self.assertRaises(ValueError):
                list(first_locations(bad, prefix_of(A), 0, 1))
        with self.assertRaises(ValueError):
            list(first_locations(block, prefix_of(A) + 1, 0, 1))
        raw = bytearray(zlib.decompress(block[4:]))
        raw[-1] = 0  # Invalid run length must not become a valid normalized record.
        with self.assertRaises(ValueError):
            list(first_locations(struct.pack('<I', len(raw)) + zlib.compress(raw), prefix_of(A), 0, 1))


if __name__ == '__main__':
    unittest.main()
