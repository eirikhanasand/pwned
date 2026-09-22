import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from compact_index import Index, build_index

WORKER = sys.argv.pop(1)


class RewriteTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.a, self.b, self.c = [hashlib.sha1(v).digest() for v in (b'a', b'b', b'c')]
        self.sources = []

    def source(self, names, rows):
        path = self.root / f'input-{len(self.sources)}'
        receipt = build_index(path, names, sorted(rows), reserve=0)
        self.sources.append((path, names, rows, receipt['sha256']))
        return path

    def run_worker(self, reserve=0, bad_checksum=False):
        lines = [str(len(self.sources))]
        for path, names, rows, sha in self.sources:
            lines.extend([str(path), '0' * 64 if bad_checksum else sha, str(len(names)), *names])
        manifest = self.root / 'manifest'
        manifest.write_text('\n'.join(lines) + '\n')
        return subprocess.run([WORKER, str(manifest), str(self.root / 'output'), str(reserve), '2'],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_persisted_records_catalog_counts_and_sources(self):
        self.source(['one.txt', 'two.txt'],
                    [(self.a, 0, 4640, 1), (self.a, 0, 1839686, 2), (self.b, 1, 7, 4)])
        self.source(['one_sorted.txt', 'two_sorted.txt', 'other/one_sorted.txt'],
                    [(self.a, 0, 3717822, 2), (self.c, 0, 99, 1),
                     (self.b, 1, 90, 4), (self.a, 2, 12010103436, 1)])
        result = self.run_worker()
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.root / 'output').open('rb') as f:
            checksum = hashlib.file_digest(f, 'sha256').hexdigest()
        import json
        receipt = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(receipt['sha256'], checksum)
        self.assertEqual(receipt['filesBefore'], 5)
        self.assertEqual(receipt['filesAfter'], 4)
        self.assertTrue(receipt['savedRecordsVerified'])
        index = Index(self.root / 'output')
        try:
            self.assertEqual(index.files, ['one.txt', 'two.txt', 'one_sorted.txt', 'other/one_sorted.txt'])
            expected = sorted([(self.a, 0, 4640, 1), (self.a, 3, 12010103436, 1),
                               (self.b, 1, 7, 1), (self.c, 2, 99, 1)])
            self.assertEqual(list(index.records()), expected)
        finally:
            index.close()
        for path, names, rows, sha in self.sources:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), sha)
        self.assertNotEqual(self.run_worker().returncode, 0)  # Never overwrite a release.

    def test_bad_checksum_and_disk_reserve_never_publish(self):
        self.source(['one.txt'], [(self.a, 0, 1, 1)])
        for kwargs in ({'bad_checksum': True}, {'reserve': 10**18}):
            result = self.run_worker(**kwargs)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / 'output').exists())

    def test_corrupt_input_fails_without_changing_it(self):
        path = self.source(['one.txt'], [(self.a, 0, 1, 1)])
        data = bytearray(path.read_bytes())
        data[-1] ^= 255
        path.write_bytes(data)
        result = self.run_worker()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'output').exists())
        self.assertEqual(path.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
