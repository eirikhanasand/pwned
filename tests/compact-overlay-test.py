import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('overlay', Path(__file__).parents[1] / 'scripts/import-compact-overlay.py')
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)
from compact_index import Index


def metadata(data, lines=None):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest().upper(),
            'lines': lines if lines is not None else len(data.splitlines()),
            'newlines': data.count(b'\n'), 'terminated': bool(data) and data.endswith(b'\n')}


class OverlayTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'files').mkdir()
        self.rows = []

    def source(self, name, lines, terminated=True):
        plaintext = b'\n'.join(lines) + (b'\n' if lines and terminated else b'')
        ordered = [hashlib.sha1(line).hexdigest().upper().encode() for line in lines]
        unique = sorted(set(ordered))
        raw = b'\n'.join(ordered) + (b'\n' if lines and terminated else b'')
        hashes = b''.join(h + b'\n' for h in unique)
        mapping = b''.join(struct.pack('<Q', unique.index(h) + 1) for h in ordered)
        hp, mp = f'files/{name}.sha1', f'files/{name}.sha1.lines'
        (self.root / hp).write_bytes(hashes)
        (self.root / mp).write_bytes(mapping)
        row = {'file': name, 'source': metadata(plaintext, len(lines)),
               'rawOutput': metadata(raw, len(lines)), 'output': metadata(hashes, len(unique)),
               'lineMap': metadata(mapping), 'outputPath': hp, 'lineMapPath': mp,
               'deduplicated': True}
        self.rows.append(row)
        (self.root / 'converted.json').write_text(json.dumps(self.rows))
        return row

    def test_round_trip_with_duplicates_empty_and_unterminated(self):
        self.source('one.txt', [b'a', b'a', b'b', b'a'], False)
        self.source('two.txt', [b'b', b'', b'a'])
        self.source('empty.txt', [], False)
        rows, plan = overlay.selection(self.root, 100)
        target = self.root / 'overlay.pwnidx'
        report = overlay.build(self.root, target, rows, plan, 10**9, 0)
        self.assertEqual(report['occurrences'], 7)
        self.assertTrue(report['savedProvenanceVerified'])
        self.assertFalse(report['inputsDeleted'])
        index = Index(target)
        try:
            answer = index.lookup(hashlib.sha1(b'a').digest())
            self.assertEqual(answer['count'], 4)
            self.assertEqual({x['file']: x['lineRanges'] for x in answer['files']},
                             {'one.txt': [[1, 2], [4, 4]], 'two.txt': [[3, 3]]})
            self.assertEqual(sum(r[3] for r in index.records()), 7)
        finally:
            index.close()
        with self.assertRaises(FileExistsError):
            overlay.build(self.root, target, rows, plan, 10**9, 0)

    def test_small_file_restores_original_names_and_local_lines(self):
        row = self.source('small.txt', [b'a', b'b', b'a'])
        cleanup = {'smallFile': 'small.txt', 'smallLines': 3,
                   'smallSha256': row['source']['sha256'], 'mergedFiles': [
                       {'file': 'first.txt', 'smallLine': 1, 'lineCount': 2},
                       {'file': 'second.txt', 'smallLine': 3},
                       {'file': 'empty.txt', 'smallLine': 4, 'lineCount': 0}]}
        catalog, packed = overlay.load_records(self.root, self.rows, cleanup)
        actual = [(catalog[fid], line) for digest, fid, line in map(overlay.PACKED.unpack, packed)
                  if digest == hashlib.sha1(b'a').digest()]
        self.assertEqual(actual, [('first.txt', 1), ('second.txt', 1)])
        for key, value in [('smallLines', 4), ('smallSha256', 'BAD')]:
            with self.assertRaises(ValueError):
                overlay.load_records(self.root, self.rows, {**cleanup, key: value})
        bad = copy.deepcopy(cleanup)
        bad['mergedFiles'][1]['smallLine'] = 2
        with self.assertRaises(ValueError):
            overlay.load_records(self.root, self.rows, bad)
        with self.assertRaises(ValueError):
            overlay.load_records(self.root, self.rows, {})

    def test_checksums_mapping_and_prededupe_counts_are_required(self):
        self.source('one.txt', [b'a', b'b', b'a'])
        for field, key, value in [('rawOutput', 'lines', 2), ('rawOutput', 'sha256', 'BAD'),
                                  ('output', 'sha256', 'BAD'), ('lineMap', 'sha256', 'BAD')]:
            rows = copy.deepcopy(self.rows)
            rows[0][field][key] = value
            with self.assertRaises(ValueError):
                overlay.load_records(self.root, rows, {})
        row = self.rows[0]
        path = self.root / row['lineMapPath']
        data = struct.pack('<QQQ', 1, 1, 1)
        path.write_bytes(data)
        row['lineMap'] = metadata(data)
        with self.assertRaisesRegex(ValueError, 'reconstruction'):
            overlay.load_records(self.root, self.rows, {})
        data = struct.pack('<QQQ', 0, 1, 1)
        path.write_bytes(data)
        row['lineMap'] = metadata(data)
        with self.assertRaisesRegex(ValueError, 'ordinal'):
            overlay.load_records(self.root, self.rows, {})

    def test_limits_selection_and_paths(self):
        self.source('one.txt', [b'a'])
        self.source('two.txt', [b'a', b'b'])
        rows, plan = overlay.selection(self.root, 1)
        self.assertEqual(plan['files'], ['one.txt'])
        self.assertEqual(plan['remainingFinalizedFiles'], 1)
        for memory, reserve in [(1, 0), (10**9, 10**18)]:
            with self.assertRaises(RuntimeError):
                overlay.build(self.root, self.root / 'blocked', rows, plan, memory, reserve)
            self.assertFalse((self.root / 'blocked').exists())
        rows[0]['outputPath'] = '../escape'
        with self.assertRaises(ValueError):
            overlay.load_records(self.root, rows, {})

    def test_full_reader_detects_incorrect_unique_count(self):
        self.source('one.txt', [b'a'])
        rows, plan = overlay.selection(self.root, 1)
        path = self.root / 'overlay.pwnidx'
        overlay.build(self.root, path, rows, plan, 10**9, 0)
        with path.open('r+b') as stream:
            stream.seek(16)
            stream.write(struct.pack('<Q', 2))
        index = Index(path)
        try:
            with self.assertRaisesRegex(ValueError, 'unique hash count'):
                list(index.records())
        finally:
            index.close()


if __name__ == '__main__':
    unittest.main()
