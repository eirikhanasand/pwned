import { promises as fs } from 'fs'
import path from 'path'

const PASSWORDS_DIR = path.join(process.cwd(), 'passwords')
const LOOKUP_FILE = 'lookup.txt'
const CACHE_TTL_MS = 5 * 60 * 1000

type PasswordIndexEntry = {
    dataset: string
    file: string
    fullPath: string
    start: string
    end: string
}

type PasswordIndexCache = {
    createdAt: number
    entries: PasswordIndexEntry[]
    datasets: string[]
    missingFiles: string[]
    unsortedDatasets: string[]
}

let cache: PasswordIndexCache | null = null
let pendingLoad: Promise<PasswordIndexCache> | null = null

function comparePasswords(left: string, right: string): number {
    return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'))
}

async function listDatasetDirs(): Promise<string[]> {
    const entries = await fs.readdir(PASSWORDS_DIR, { withFileTypes: true })
    const directories = entries
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name)
        .sort((left, right) => left.localeCompare(right))

    const checks = await Promise.all(directories.map(async directory => {
        try {
            await fs.access(path.join(PASSWORDS_DIR, directory, LOOKUP_FILE))
            return directory
        } catch {
            return null
        }
    }))

    return checks.filter((value): value is string => Boolean(value))
}

async function loadLookupFile(dataset: string): Promise<PasswordIndexEntry[]> {
    const datasetDir = path.join(PASSWORDS_DIR, dataset)
    const lookupPath = path.join(datasetDir, LOOKUP_FILE)
    const raw = await fs.readFile(lookupPath, 'utf8')
    const lines = raw.split(/\r?\n/).map(line => line.replace(/\r$/, ''))

    if (lines.at(-1) === '') {
        lines.pop()
    }

    if (lines.length % 3 !== 0) {
        throw new Error(`Lookup file ${lookupPath} has ${lines.length} non-empty lines, expected a multiple of 3`)
    }

    const results: PasswordIndexEntry[] = []

    for (let index = 0; index < lines.length; index += 3) {
        const file = lines[index]
        const start = lines[index + 1]
        const end = lines[index + 2]
        const fullPath = path.join(datasetDir, file)

        results.push({
            dataset,
            file,
            fullPath,
            start,
            end
        })
    }

    return results
}

async function buildIndex(): Promise<PasswordIndexCache> {
    const datasets = await listDatasetDirs()
    const allEntries = await Promise.all(datasets.map(loadLookupFile))
    const unsortedDatasets = allEntries
        .map((entries, index) => {
            for (let entryIndex = 1; entryIndex < entries.length; entryIndex += 1) {
                const previous = entries[entryIndex - 1]
                const current = entries[entryIndex]
                if (
                    comparePasswords(previous.start, current.start) > 0 ||
                    (
                        comparePasswords(previous.start, current.start) === 0 &&
                        comparePasswords(previous.end, current.end) > 0
                    )
                ) {
                    return datasets[index]
                }
            }

            return null
        })
        .filter((value): value is string => Boolean(value))

    const entries = allEntries
        .flat()
        .sort((left, right) => {
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

    const fileChecks = await Promise.all(entries.map(async entry => {
        try {
            await fs.access(entry.fullPath)
            return null
        } catch {
            return entry.fullPath
        }
    }))

    const missingFiles = fileChecks.filter((value): value is string => Boolean(value))

    return {
        createdAt: Date.now(),
        entries,
        datasets,
        missingFiles,
        unsortedDatasets
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

export async function findCandidateFiles(password: string): Promise<PasswordIndexEntry[]> {
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
        unsortedDatasets: index.unsortedDatasets
    }
}
