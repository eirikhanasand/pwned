import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase, main, mock

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from compact_index import build_index, Index

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).parents[1] / 'scripts/publish-compact-overlay.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublishTest(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source.pwnidx'
        self.target = self.root / 'release.pwnidx'
        self.digest = hashlib.sha1(b'fixture').digest()
        receipt = build_index(self.source, ['one.txt'], [(self.digest, 0, 12, 2)], reserve=0)
        receipt.update(state='verified', savedProvenanceVerified=True,
                       originalOrderHashChecksumsVerified=True, originalLines=2)
        Path(str(self.source) + '.receipt.json').write_text(json.dumps(receipt))
        self.receipt = receipt

    def no_wait(self, *args):
        raise AssertionError('unexpected space wait')

    def test_publish_retains_source_and_is_idempotent(self):
        report = publisher.publish(self.source, self.target, 0, self.no_wait)
        self.assertEqual(report['state'], 'published')
        self.assertEqual(self.source.read_bytes(), self.target.read_bytes())
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o400)
        self.assertEqual(publisher.publish(self.source, self.target, 0, self.no_wait), report)
        index = Index(self.target)
        try:
            self.assertEqual(index.lookup(self.digest)['files'][0]['lineRanges'], [[12, 13]])
        finally:
            index.close()

    def test_interrupted_copy_resumes_verified_prefix(self):
        original = publisher.os.fsync
        calls = 0

        def interrupt(fd):
            nonlocal calls
            original(fd)
            calls += 1
            # Intent file and directory, followed by first copied block.
            if calls == 3:
                raise InterruptedError('simulated interruption')

        with mock.patch.object(publisher, 'CHUNK', 1024**2), mock.patch.object(publisher.os, 'fsync', interrupt):
            with self.assertRaises(InterruptedError):
                publisher.publish(self.source, self.target, 0, self.no_wait)
        partial = Path(str(self.target) + '.copy.partial')
        self.assertEqual(partial.stat().st_size, 1024**2)
        self.assertFalse(self.target.exists())
        publisher.publish(self.source, self.target, 0, self.no_wait)
        self.assertEqual(self.target.read_bytes(), self.source.read_bytes())

    def test_corrupt_partial_is_never_discarded(self):
        intent = Path(str(self.target) + '.publish.json')
        intent.write_text(json.dumps({'sourceReceipt': self.receipt, 'target': self.target.name}))
        partial = Path(str(self.target) + '.copy.partial')
        partial.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'differs'):
            publisher.publish(self.source, self.target, 0, self.no_wait)
        self.assertEqual(partial.read_bytes(), b'corrupt')
        self.assertFalse(self.target.exists())

    def test_resume_after_verified_copy_before_atomic_link(self):
        with mock.patch.object(publisher.os, 'link', side_effect=InterruptedError('before publication')):
            with self.assertRaises(InterruptedError):
                publisher.publish(self.source, self.target, 0, self.no_wait)
        staged = Path(str(self.target) + '.copy.partial')
        self.assertEqual(staged.stat().st_mode & 0o777, 0o400)
        self.assertFalse(self.target.exists())
        publisher.publish(self.source, self.target, 0, self.no_wait)
        self.assertEqual(self.target.read_bytes(), self.source.read_bytes())
        self.assertFalse(staged.exists())

    def test_disk_wait_retains_source_then_continues(self):
        current = [0]
        waits = []

        def wait(state, saved, total):
            waits.append((state, saved, total))
            current[0] = 10**12

        with mock.patch.object(publisher.shutil, 'disk_usage', lambda _: mock.Mock(free=current[0])):
            publisher.publish(self.source, self.target, 1000, wait)
        self.assertEqual(waits, [('waiting_for_disk', 0, self.receipt['bytes'])])
        self.assertTrue(self.source.exists())

    def test_bad_receipt_checksum_and_master_target_fail(self):
        receipt_path = Path(str(self.source) + '.receipt.json')
        bad = {**self.receipt, 'savedProvenanceVerified': False}
        receipt_path.write_text(json.dumps(bad))
        with self.assertRaisesRegex(ValueError, 'verification receipt'):
            publisher.publish(self.source, self.target, 0, self.no_wait)
        receipt_path.write_text(json.dumps({**self.receipt, 'sha256': '0' * 64}))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            publisher.publish(self.source, self.target, 0, self.no_wait)
        self.assertFalse(self.target.exists())
        with self.assertRaisesRegex(ValueError, 'target'):
            publisher.publish(self.source, self.root / 'master.pwnidx', 0, self.no_wait)

    def test_unknown_existing_output_not_overwritten(self):
        self.target.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            publisher.publish(self.source, self.target, 0, self.no_wait)
        self.assertEqual(self.target.read_bytes(), b'existing')


if __name__ == '__main__':
    main()
