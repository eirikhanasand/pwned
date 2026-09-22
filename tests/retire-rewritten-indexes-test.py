import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('retirement', Path(__file__).parents[1] / 'scripts/retire-rewritten-indexes.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RetirementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.output, self.source = root / 'new.pwnidx', root / 'old.pwnidx'
        self.output.write_bytes(b'new verified unique records')
        self.source.write_bytes(b'old duplicate records')
        def metadata(path):
            return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'bytes': path.stat().st_size}
        self.receipt = {**metadata(self.output), 'sources': [metadata(self.source)],
                        'physicalDeduplication': True, 'savedRecordsVerified': True, 'state': 'verified'}
        self.receipt_path = Path(str(self.output) + '.receipt.json')
        self.receipt_path.write_text(json.dumps(self.receipt))
        self.mounts = {str(self.output)}

    def test_dry_run_retirement_and_retry(self):
        report = module.retire(self.output, [self.source], self.mounts)
        self.assertEqual(report['state'], 'planned')
        self.assertTrue(self.source.exists())
        report = module.retire(self.output, [self.source], self.mounts, True)
        self.assertEqual(report['state'], 'retired')
        self.assertFalse(self.source.exists())
        self.assertTrue(self.output.exists())
        self.assertEqual(module.retire(self.output, [self.source], self.mounts, True), report)

    def test_rejects_wrong_live_mounts_and_input_selection(self):
        for mounts in (set(), self.mounts | {str(self.source)}):
            with self.assertRaises(ValueError):
                module.retire(self.output, [self.source], mounts, True)
        with self.assertRaises(ValueError):
            module.retire(self.output, [self.output], self.mounts, True)
        self.assertTrue(self.source.exists())

    def test_changed_source_or_output_never_deleted(self):
        for path in (self.output, self.source):
            old = path.read_bytes()
            path.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                module.retire(self.output, [self.source], self.mounts, True)
            self.assertTrue(self.source.exists())
            path.write_bytes(old)

    def test_missing_source_and_unverified_receipt_rejected(self):
        self.receipt['savedRecordsVerified'] = False
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaises(ValueError):
            module.retire(self.output, [self.source], self.mounts, True)
        self.receipt['savedRecordsVerified'] = True
        self.receipt_path.write_text(json.dumps(self.receipt))
        self.source.unlink()
        with self.assertRaises(ValueError):
            module.retire(self.output, [self.source], self.mounts, True)


if __name__ == '__main__':
    unittest.main()
