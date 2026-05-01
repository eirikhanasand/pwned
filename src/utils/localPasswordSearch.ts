import { spawn } from 'child_process'
import { findCandidateEntries, type PasswordSourceEntry } from '#utils/passwordIndex.ts'
import { searchSortedFileExactMatch } from '#utils/sortedFileSearch.ts'

export async function hasLocalPassword(password: string): Promise<boolean> {
    const candidates = await findCandidateEntries(password)
    const sortedCandidates = candidates.filter((candidate): candidate is PasswordSourceEntry & { kind: 'sorted' } => candidate.kind === 'sorted')
    const lookupCandidates = candidates.filter((candidate): candidate is PasswordSourceEntry & { kind: 'lookup' } => candidate.kind === 'lookup')

    for (const candidate of sortedCandidates) {
        if (await searchSortedFileExactMatch(candidate.fullPath, password)) {
            return true
        }
    }

    if (!lookupCandidates.length) {
        return false
    }

    return hasLookupPassword(password, lookupCandidates)
}

function hasLookupPassword(password: string, candidates: PasswordSourceEntry[]): Promise<boolean> {
    return new Promise((resolve, reject) => {
        let settled = false
        const child = spawn('rg', ['-a', '-F', '-x', '-m', '1', '-n', '-H', '--', password, ...candidates.map(candidate => candidate.fullPath)], {
            stdio: ['ignore', 'pipe', 'pipe']
        })

        child.stdout.on('data', (data: Buffer) => {
            if (!settled && data.byteLength > 0) {
                settled = true
                child.kill('SIGTERM')
                resolve(true)
            }
        })

        child.stderr.on('data', (data: Buffer) => {
            const message = data.toString().trim()
            if (message && !settled) {
                settled = true
                child.kill('SIGTERM')
                reject(new Error(message))
            }
        })

        child.on('error', error => {
            if (!settled) {
                settled = true
                reject(error)
            }
        })

        child.on('close', code => {
            if (!settled) {
                settled = true
                resolve(code === 0)
            }
        })
    })
}
