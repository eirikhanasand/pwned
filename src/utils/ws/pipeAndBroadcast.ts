import { spawn } from 'child_process'
import broadcast, { clientsMap } from './broadcast.ts'

export default function execPipeAndBroadcast(id: string, password: string): void {
    let childLeftover = ''
    let findLeftover = ''
    let remaining = 2

    function parseLine(data: Buffer, isFind: boolean) {
        let leftover = isFind ? findLeftover : childLeftover
        const text = leftover + data.toString()
        const lines = text.split('\n')
        leftover = lines.pop() || ''

        lines.forEach(rawLine => {
            const line = rawLine.trim()
            if (!line) return

            console.log("recieved line", rawLine)
            // Matches "file:line" or "file:line:match"
            const match = line.match(/^(.+):(\d+)(?::(.*))?$/)
            if (match) {
                console.log(match)
                const [, file, lineNum, matchText] = match
                broadcast(id, 'update', {
                    ok: false,
                    file,
                    line: parseInt(lineNum, 10),
                    ...(matchText ? { match: matchText } : {})
                })
            } else {
                // debug unmatched lines (helpful while testing)
                broadcast(id, 'update', { debug: line })
            }
        })

        if (isFind) findLeftover = leftover
        else childLeftover = leftover
    }

    // Spawn ripgrep (rg)
    const child = spawn('rg', ['-a', '-x', '-n', '--max-depth', '1', '--', password], {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: `${process.cwd()}/passwords`
    })

    // Spawn find_all.sh directly (script must be executable)
    const findChild = spawn('./find_all.sh', [password], {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: `${process.cwd()}/passwords`
    })

    // Debug: broadcast PIDs
    broadcast(id, 'update', { debug: `spawned rg pid=${child.pid}, find_all pid=${findChild.pid}` })

    // Attach stdout handlers
    child.stdout.on('data', (data: Buffer) => parseLine(data, false))
    findChild.stdout.on('data', (data: Buffer) => parseLine(data, true))

    // Attach stderr handlers (also broadcast so you can see script errors)
    child.stderr.on('data', (err: Buffer) => {
        broadcast(id, 'update', { error: `rg stderr: ${err.toString()}` })
    })
    findChild.stderr.on('data', (err: Buffer) => {
        broadcast(id, 'update', { error: `find_all stderr: ${err.toString()}` })
    })

    // Spawn error handlers (if spawn fails)
    child.on('error', (err) => {
        broadcast(id, 'update', { error: `rg spawn error: ${err.message}` })
    })
    findChild.on('error', (err) => {
        broadcast(id, 'update', { error: `find_all spawn error: ${err.message}` })
    })

    // Close handler for both processes
    function onChildClose(code: number | null, signal: NodeJS.Signals | null) {
        remaining -= 1

        // If both have closed, flush leftovers properly (add newline)
        if (remaining <= 0) {
            // flush any leftover line — IMPORTANT: append a newline so leftover is treated as full line
            if (childLeftover) parseLine(Buffer.from('\n'), false)
            if (findLeftover) parseLine(Buffer.from('\n'), true)

            broadcast(id, 'update', { done: true }, true)
            clientsMap.delete(id)
        } else {
            // Broadcast partial status (optional)
            broadcast(id, 'update', { debug: `one process closed (remaining=${remaining}) code=${code} signal=${signal}` })
        }
    }

    child.on('close', (code, signal) => onChildClose(code, signal))
    findChild.on('close', (code, signal) => onChildClose(code, signal))
}
