import { promises as fs } from 'fs'
import path from 'path'

const passwordsDir = process.env.PASSWORDS_DIR || path.join(process.cwd(), 'passwords')
const sampleLimit = Number(process.env.SAMPLE_LIMIT || 3)

function comparePasswords(left, right) {
    return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'))
}

async function readLookupEntries(datasetDir) {
    const lookupPath = path.join(datasetDir, 'lookup.txt')
    const raw = await fs.readFile(lookupPath, 'utf8')
    const lines = raw.split(/\r?\n/).map(line => line.replace(/\r$/, ''))

    if (lines.at(-1) === '') {
        lines.pop()
    }

    if (lines.length % 3 !== 0) {
        throw new Error(`${lookupPath} has ${lines.length} non-empty lines, expected a multiple of 3`)
    }

    const entries = []
    for (let index = 0; index < lines.length; index += 3) {
        entries.push({
            file: lines[index],
            start: lines[index + 1],
            end: lines[index + 2]
        })
    }
    return entries
}

async function readFileBoundary(filePath, mode) {
    const raw = await fs.readFile(filePath, 'utf8')
    const lines = raw.split(/\r?\n/)
    if (lines.at(-1) === '') {
        lines.pop()
    }
    if (!lines.length) {
        throw new Error(`${filePath} is empty`)
    }
    return mode === 'first' ? lines[0] : lines.at(-1)
}

async function main() {
    const dirents = await fs.readdir(passwordsDir, { withFileTypes: true })
    const datasets = dirents.filter(entry => entry.isDirectory()).map(entry => entry.name).sort()
    const results = []
    const warnings = []
    const errors = []

    for (const dataset of datasets) {
        const datasetDir = path.join(passwordsDir, dataset)
        const lookupPath = path.join(datasetDir, 'lookup.txt')

        try {
            await fs.access(lookupPath)
        } catch {
            continue
        }

        let entries
        try {
            entries = await readLookupEntries(datasetDir)
        } catch (error) {
            errors.push(error instanceof Error ? error.message : String(error))
            continue
        }

        const datasetFiles = await fs.readdir(datasetDir)
        const sortedCandidates = await Promise.all(datasetFiles
            .filter(file => file.endsWith('.txt') && file.includes('_sorted'))
            .map(async file => {
                const stat = await fs.stat(path.join(datasetDir, file))
                return { file, sizeBytes: stat.size }
            }))
        const sortedMaster = sortedCandidates.sort((left, right) => right.sizeBytes - left.sizeBytes)[0] || null

        let sorted = true
        for (let index = 1; index < entries.length; index += 1) {
            if (comparePasswords(entries[index - 1].start, entries[index].start) > 0) {
                sorted = false
                warnings.push(`${lookupPath} is not sorted at entry ${index + 1}`)
                break
            }
        }

        let shardBytes = 0
        for (const entry of entries) {
            try {
                const stat = await fs.stat(path.join(datasetDir, entry.file))
                shardBytes += stat.size
            } catch (error) {
                errors.push(error instanceof Error ? error.message : String(error))
            }
        }

        const samples = new Set([0, Math.max(0, entries.length - 1)])
        for (let index = 1; index < Math.min(entries.length - 1, sampleLimit); index += 1) {
            samples.add(Math.floor((index * entries.length) / (sampleLimit + 1)))
        }

        for (const sampleIndex of samples) {
            const entry = entries[sampleIndex]
            const filePath = path.join(datasetDir, entry.file)
            let firstLine
            let lastLine
            try {
                [firstLine, lastLine] = await Promise.all([
                    readFileBoundary(filePath, 'first'),
                    readFileBoundary(filePath, 'last')
                ])
            } catch (error) {
                errors.push(error instanceof Error ? error.message : String(error))
                continue
            }

            if (firstLine !== entry.start || lastLine !== entry.end) {
                errors.push(`${filePath} boundaries do not match lookup.txt`)
            }
        }

        if (sortedMaster && shardBytes < sortedMaster.sizeBytes) {
            warnings.push(`${dataset}: lookup shards cover ${shardBytes} bytes but sorted master ${sortedMaster.file} is ${sortedMaster.sizeBytes} bytes`)
        }

        results.push({
            dataset,
            shards: entries.length,
            sampledFiles: samples.size,
            sorted,
            shardBytes,
            sortedMaster
        })
    }

    console.log(JSON.stringify({
        ok: errors.length === 0,
        checkedAt: new Date().toISOString(),
        datasetCount: results.length,
        errors,
        warnings,
        results
    }, null, 2))

    if (errors.length > 0) {
        process.exit(1)
    }
}

main().catch(err => {
    console.error(err instanceof Error ? err.message : String(err))
    process.exit(1)
})
