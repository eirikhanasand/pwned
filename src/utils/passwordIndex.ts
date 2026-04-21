import { promises as fs } from 'fs'
import path from 'path'
import { readFileBoundaries } from '#utils/sortedFileSearch.ts'

const PASSWORDS_DIR = process.env.PASSWORDS_DIR || path.join(process.cwd(), 'passwords')
const LOOKUP_FILE = 'lookup.txt'
const CACHE_TTL_MS = 5 * 60 * 1000

export type PasswordSourceEntry = {
    kind: 'lookup' | 'sorted'
    dataset: string
    file: string
    fullPath: string
    start: string
    end: string
    sizeBytes: number
}

type PasswordIndexCache = {
    createdAt: number
    entries: PasswordSourceEntry[]
    datasets: string[]
    missingFiles: string[]
    unsortedDatasets: string[]
    sortedDatasets: string[]
    coverageWarnings: string[]
}

let cache: PasswordIndexCache | null = null
let pendingLoad: Promise<PasswordIndexCache> | null = null

function comparePasswords(left: string, right: string): number {
    return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'))
}

function parseLookupLines(raw: string, lookupPath: string): string[] {
    const lines = raw.split(/\r?\n/).map(line => line.replace(/\r$/, ''))

    if (lines.at(-1) === '') {
        lines.pop()
    }

    if (lines.length % 3 !== 0) {
        throw new Error(`Lookup file ${lookupPath} has ${lines.length} non-empty lines, expected a multiple of 3`)
    }

    return lines
}

async function readDatasetDirectories(): Promise<string[]> {
    const entries = await fs.readdir(PASSWORDS_DIR, { withFileTypes: true })
    return entries
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name)
        .sort((left, right) => left.localeCompare(right))
}

async function findSortedMaster(datasetDir: string): Promise<{ file: string, fullPath: string, sizeBytes: number } | null> {
    const entries = await fs.readdir(datasetDir, { withFileTypes: true })
    const candidates = await Promise.all(entries
        .filter(entry => entry.isFile())
        .map(async entry => {
            if (!entry.name.endsWith('.txt') || !entry.name.includes('_sorted')) {
                return null
            }

            const fullPath = path.join(datasetDir, entry.name)
            const stat = await fs.stat(fullPath)

            return {
                file: entry.name,
                fullPath,
                sizeBytes: stat.size
            }
        }))

    const sortedCandidates = candidates.filter((value): value is { file: string, fullPath: string, sizeBytes: number } => Boolean(value))
    if (!sortedCandidates.length) {
        return null
    }

    return sortedCandidates.sort((left, right) => right.sizeBytes - left.sizeBytes)[0]
}

async function loadLookupEntries(dataset: string, datasetDir: string): Promise<{ entries: PasswordSourceEntry[], shardBytes: number, unsorted: boolean }> {
    const lookupPath = path.join(datasetDir, LOOKUP_FILE)
    const raw = await fs.readFile(lookupPath, 'utf8')
    const lines = parseLookupLines(raw, lookupPath)
    const entries: PasswordSourceEntry[] = []
    let shardBytes = 0
    let unsorted = false

    for (let index = 0; index < lines.length; index += 3) {
        const file = lines[index]
        const start = lines[index + 1]
        const end = lines[index + 2]
        const fullPath = path.join(datasetDir, file)
        const stat = await fs.stat(fullPath)
        shardBytes += stat.size

        const current: PasswordSourceEntry = {
            kind: 'lookup',
            dataset,
            file,
            fullPath,
            start,
            end,
            sizeBytes: stat.size
        }

        const previous = entries.at(-1)
        if (previous) {
            if (
                comparePasswords(previous.start, current.start) > 0 ||
                (
                    comparePasswords(previous.start, current.start) === 0 &&
                    comparePasswords(previous.end, current.end) > 0
                )
            ) {
                unsorted = true
            }
        }

        entries.push(current)
    }

    return { entries, shardBytes, unsorted }
}

async function buildIndex(): Promise<PasswordIndexCache> {
    const datasets = await readDatasetDirectories()
    const entries: PasswordSourceEntry[] = []
    const missingFiles: string[] = []
    const unsortedDatasets: string[] = []
    const sortedDatasets: string[] = []
    const coverageWarnings: string[] = []

    for (const dataset of datasets) {
        const datasetDir = path.join(PASSWORDS_DIR, dataset)
        const lookupPath = path.join(datasetDir, LOOKUP_FILE)
        const sortedMaster = await findSortedMaster(datasetDir)
        const hasLookup = await fs.access(lookupPath).then(() => true).catch(() => false)

        let lookupEntries: PasswordSourceEntry[] = []
        let shardBytes = 0

        if (hasLookup) {
            const loadedLookup = await loadLookupEntries(dataset, datasetDir)
            lookupEntries = loadedLookup.entries
            shardBytes = loadedLookup.shardBytes

            if (loadedLookup.unsorted) {
                unsortedDatasets.push(dataset)
            }
        }

        if (sortedMaster) {
            const boundaries = await readFileBoundaries(sortedMaster.fullPath)
            entries.push({
                kind: 'sorted',
                dataset,
                file: sortedMaster.file,
                fullPath: sortedMaster.fullPath,
                start: boundaries.firstLine,
                end: boundaries.lastLine,
                sizeBytes: sortedMaster.sizeBytes
            })
            sortedDatasets.push(dataset)

            if (shardBytes > 0 && shardBytes < sortedMaster.sizeBytes) {
                coverageWarnings.push(`${dataset}: lookup shards cover ${shardBytes} bytes but sorted master ${sortedMaster.file} is ${sortedMaster.sizeBytes} bytes`)
            }
            continue
        }

        entries.push(...lookupEntries)
    }

    const fileChecks = await Promise.all(entries.map(async entry => {
        try {
            await fs.access(entry.fullPath)
            return null
        } catch {
            return entry.fullPath
        }
    }))

    missingFiles.push(...fileChecks.filter((value): value is string => Boolean(value)))

    entries.sort((left, right) => {
        const startComparison = comparePasswords(left.start, right.start)
        if (startComparison !== 0) {
            return startComparison
        }

        const endComparison = comparePasswords(left.end, right.end)
        if (endComparison !== 0) {
            return endComparison
        }

        return left.fullPath.localeCompare(right.fullPath)
    })

    return {
        createdAt: Date.now(),
        entries,
        datasets,
        missingFiles,
        unsortedDatasets,
        sortedDatasets,
        coverageWarnings
    }
}

export async function getPasswordIndex(forceRefresh = false): Promise<PasswordIndexCache> {
    const now = Date.now()
    if (!forceRefresh && cache && now - cache.createdAt < CACHE_TTL_MS) {
        return cache
    }

    if (!pendingLoad) {
        pendingLoad = buildIndex()
            .then(result => {
                cache = result
                return result
            })
            .finally(() => {
                pendingLoad = null
            })
    }

    return pendingLoad
}

export async function findCandidateEntries(password: string): Promise<PasswordSourceEntry[]> {
    const index = await getPasswordIndex()
    return index.entries.filter(entry =>
        comparePasswords(password, entry.start) >= 0 &&
        comparePasswords(password, entry.end) <= 0
    )
}

export async function getPasswordIndexStatus(forceRefresh = false) {
    const index = await getPasswordIndex(forceRefresh)
    return {
        ok: index.missingFiles.length === 0,
        checkedAt: new Date(index.createdAt).toISOString(),
        datasetCount: index.datasets.length,
        shardCount: index.entries.length,
        missingFiles: index.missingFiles,
        unsortedDatasets: index.unsortedDatasets,
        sortedDatasets: index.sortedDatasets,
        coverageWarnings: index.coverageWarnings
    }
}
