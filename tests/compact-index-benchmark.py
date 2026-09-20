"""Synthetic dense-prefix benchmark; not a full-dataset performance claim."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('compact_index', Path(__file__).parents[1] / 'scripts/compact_index.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def percentiles(values):
    ordered = sorted(values)
    return {'medianMs': statistics.median(ordered), 'p95Ms': ordered[int((len(ordered)-1)*.95)],
            'maxMs': max(ordered), 'queries': len(values)}


root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.gettempdir())
with tempfile.TemporaryDirectory(prefix='pwned-index-benchmark-', dir=root) as directory:
    # 25,000 entries per prefix models bucket density of ~26 billion hashes.
    # Only 16 buckets are materialized; this is explicitly a sizing prototype.
    buckets, per_bucket = 16, 25000
    queries = []
    def records():
        for prefix in range(buckets):
            values = sorted(bytes.fromhex(f'{prefix:05x}' + hashlib.sha1(f'fixture:{prefix}:{i}'.encode()).hexdigest()[5:])
                            for i in range(per_bucket))
            queries.extend(values[i] for i in (0, 100, 12000, per_bucket-1))
            for i, digest in enumerate(values):
                # Original line order is unrelated to SHA-1 order; do not make
                # provenance unrealistically compressible with sequential IDs.
                line = ((prefix * per_bucket + i) * 2654435761) % (1 << 35) + 1
                yield digest, 0, line, 1
    path = Path(directory) / 'synthetic.bin'
    build_start = time.perf_counter()
    report = module.build_index(path, ['synthetic/master.txt'], records(), reserve=0)
    build_seconds = time.perf_counter() - build_start
    index = module.Index(path)
    warm = []
    for _ in range(4):
        for digest in queries:
            start = time.perf_counter_ns()
            result = index.lookup(digest)
            warm.append((time.perf_counter_ns()-start)/1e6)
            assert result['count'] == 1 and len(result['files']) == 1
    cold = []
    if hasattr(os, 'posix_fadvise'):
        for digest in queries[::4]:
            prefix = module.prefix_of(digest)
            start, end = index.directory[prefix:prefix+2]
            # Advisory eviction of this disposable benchmark file only.
            os.posix_fadvise(index.file.fileno(), start, end-start, os.POSIX_FADV_DONTNEED)
            began = time.perf_counter_ns()
            assert index.lookup(digest)['count'] == 1
            cold.append((time.perf_counter_ns()-began)/1e6)
    index.close()
    print(json.dumps({'synthetic': True, 'hashes': report['uniqueHashes'], 'entriesPerPrefix': per_bucket,
                      'bytes': report['bytes'], 'payloadBytesPerHash': (report['bytes']-module.DIRECTORY_BYTES)/report['uniqueHashes'],
                      'buildSeconds': build_seconds, 'warm': percentiles(warm),
                      'advisoryCold': percentiles(cold) if cold else None}, indent=2))
