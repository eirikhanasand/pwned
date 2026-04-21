import { spawn } from 'child_process'
import broadcast, { clientsMap } from './broadcast.ts'
import { findCandidateEntries, type PasswordSourceEntry } from '#utils/passwordIndex.ts'
import { searchSortedFileExact } from '#utils/sortedFileSearch.ts'

export default async function execPipeAndBroadcast(id: string, password: string): Promise<void> {
    const candidates = await findCandidateEntries(password)

    if (!candidates.length) {
        broadcast(id, 'update', { debug: 'No candidate shard matched the password range.' })
        broadcast(id, 'update', { done: true }, true)
        clientsMap.delete(id)
        return
    }

    const sortedCandidates = candidates.filter((candidate): candidate is PasswordSourceEntry & { kind: 'sorted' } => candidate.kind === 'sorted')
    const lookupCandidates = candidates.filter((candidate): candidate is PasswordSourceEntry & { kind: 'lookup' } => candidate.kind === 'lookup')
    const seenFiles = new Set<string>()

    for (const candidate of sortedCandidates) {
        const found = await searchSortedFileExact(candidate.fullPath, password)
        if (!found) {
            continue
        }

        seenFiles.add(candidate.fullPath)
        broadcast(id, 'update', {
            ok: false,
            file: candidate.fullPath,
            match: password,
            source: 'sorted'
        })
    }

    if (!lookupCandidates.length) {
        broadcast(id, 'update', { done: true }, true)
        clientsMap.delete(id)
        return
    }

    let childLeftover = ''

    function parseLine(data: Buffer) {
        let leftover = childLeftover
        const text = leftover + data.toString()
        const lines = text.split('\n')
        leftover = lines.pop() || ''

        lines.forEach(rawLine => {
            const line = rawLine.trim()
            if (!line) return

            const match = line.match(/^(.+):(\d+)(?::(.*))?$/)
            if (match) {
                const [, file, lineNum, matchText] = match
                if (seenFiles.has(file)) {
                    return
                }

                broadcast(id, 'update', {
                    ok: false,
                    file,
                    line: parseInt(lineNum, 10),
                    ...(matchText ? { match: matchText } : {})
                })
            } else {
                broadcast(id, 'update', { debug: line })
            }
        })

        childLeftover = leftover
    }

    const child = spawn('rg', ['-a', '-x', '-n', '-H', '--', password, ...lookupCandidates.map(candidate => candidate.fullPath)], {
        stdio: ['ignore', 'pipe', 'pipe']
    })

    broadcast(id, 'update', {
        debug: `spawned rg pid=${child.pid} across ${candidates.length} shard${candidates.length === 1 ? '' : 's'}`,
        candidates: candidates.map(candidate => ({
            dataset: candidate.dataset,
            file: candidate.file,
            kind: candidate.kind
        }))
    })

    child.stdout.on('data', (data: Buffer) => parseLine(data))

    child.stderr.on('data', (err: Buffer) => {
        broadcast(id, 'update', { error: `rg stderr: ${err.toString()}` })
    })

    child.on('error', (err) => {
        broadcast(id, 'update', { error: `rg spawn error: ${err.message}` })
    })

    child.on('close', (code, signal) => {
        if (childLeftover) {
            parseLine(Buffer.from('\n'))
        }

        broadcast(id, 'update', {
            done: true,
            exitCode: code,
            signal
        }, true)
        clientsMap.delete(id)
    })
}
