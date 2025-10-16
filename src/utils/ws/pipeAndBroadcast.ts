import { spawn } from 'child_process'
import broadcast, { clientsMap } from './broadcast.ts'

export default function execPipeAndBroadcast(id: string, password: string): void {
    const child = spawn('rg', 
        ['-a', '-x', '-n', '--', password], 
        {stdio: ['ignore', 'pipe', 'pipe'], 
        cwd: `${process.cwd()}/passwords`}
    )

    // Pipe child stdout directly to main console for full visibility
    child.stdout.on('data', (data: Buffer) => {
        const text = data.toString()
        process.stdout.write(text)
        const lines = text.split('\n').filter(Boolean)
        lines.forEach(line => {
            const match = line.match(/(.+):(\d+):(.+)/)
            if (match) {
                const [, file, lineNumber] = match
                broadcast(id, 'update', {
                    ok: false,
                    reason: 'Matched in file',
                    file,
                    lineNumber: parseInt(lineNumber),
                })
            }
        })
    })

    child.stderr.on('data', (err: Buffer) => {
        broadcast(id, 'update', {
            ok: false,
            reason: 'Error during exec',
            error: err.toString()
        })
    })

    child.on('close', () => {
        broadcast(id, 'update', { ok: true, done: true }, true)
        clientsMap.delete(id)
    })
}
