import { spawn } from 'child_process'
import broadcast, { clientsMap } from './broadcast.ts'

export default function execPipeAndBroadcast(id: string, password: string): void {
    const child = spawn('rg',
        ['-a', '-x', '-n', '--', password],
        {
            stdio: ['ignore', 'pipe', 'pipe'],
            cwd: `${process.cwd()}/passwords`
        }
    )

    child.stdout.on('data', (data: Buffer) => {
        const text = data.toString()
        const lines = text.split('\n').filter(Boolean)
        lines.forEach(line => {
            const match = line.match(/(.+):(\d+):(.+)/)
            if (match) {
                const [, file, lineNumber] = match
                broadcast(id, 'update', {
                    ok: false,
                    file,
                    lineNumber: parseInt(lineNumber)
                })
            }
        })
    })

    child.stderr.on('data', (err: Buffer) => {
        broadcast(id, 'update', { error: err.toString() })
    })

    child.on('close', () => {
        broadcast(id, 'update', { done: true }, true)
        clientsMap.delete(id)
    })
}
