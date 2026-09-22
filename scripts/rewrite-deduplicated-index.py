"""Build and fully verify a physical replacement without modifying its inputs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

from compact_index import Index
from finalize_inventory import save_receipt


def rewrite(worker, sources, output, reserve, threads):
    output = Path(output).resolve()
    receipts, lines = [], [str(len(sources))]
    for source in sources:
        source = Path(source).resolve()
        receipt = json.loads(Path(str(source) + '.receipt.json').read_text())
        index = Index(source)
        try:
            if (not receipt.get('savedProvenanceVerified') or receipt['bytes'] != source.stat().st_size
                    or receipt['uniqueHashes'] != index.unique):
                raise ValueError('source does not match verified receipt')
            if any('\n' in name or '\r' in name for name in index.files):
                raise ValueError('unsupported catalog filename')
            lines.extend([str(source), receipt['sha256'].lower(), str(len(index.files)), *index.files])
            receipts.append({'path': str(source), 'sha256': receipt['sha256'], 'bytes': receipt['bytes'],
                             'uniqueHashes': receipt['uniqueHashes'], 'occurrences': receipt['occurrences']})
        finally:
            index.close()
    manifest = Path(str(output) + '.manifest')
    with manifest.open('x') as stream:
        stream.write('\n'.join(lines) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    started = time.time()
    report = None
    with subprocess.Popen([str(worker), str(manifest), str(output), str(reserve), str(threads)],
                          stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            print(line, end='', flush=True)
            report = json.loads(line)
            report['elapsedSeconds'] = round(time.time() - started, 1)
            save_receipt(Path(str(output) + '.status.json'), report)
        if process.wait() != 0:
            raise RuntimeError('migration failed; inputs and any partial output retained')
    if (not report or report.get('phase') != 'complete' or not report.get('savedRecordsVerified')
            or report['originalOccurrences'] != sum(r['occurrences'] for r in receipts)
            or report['retainedOccurrences'] != report['originalOccurrences'] - report['duplicateLinesRemoved'] - report['sortedMatchesRemoved']):
        raise RuntimeError('replacement receipt does not reconcile with source inventory')
    report.update(sources=receipts, state='verified', savedProvenanceVerified=True,
                  occurrences=report['retainedOccurrences'], physicalDeduplication=True)
    save_receipt(Path(str(output) + '.receipt.json'), report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--reserve-bytes', type=int, required=True)
    parser.add_argument('--threads', type=int, default=8)
    parser.add_argument('output', type=Path)
    parser.add_argument('sources', nargs='+', type=Path)
    args = parser.parse_args()
    rewrite(args.worker, args.sources, args.output, args.reserve_bytes, args.threads)
