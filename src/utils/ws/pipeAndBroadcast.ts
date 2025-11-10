import { spawn } from 'child_process'
import broadcast, { clientsMap } from './broadcast.ts'

export default function execPipeAndBroadcast(id: string, password: string): void {
    function parseLine(data: Buffer<ArrayBufferLike>) {
        const text = data.toString()
        const lines = text.split('\n').filter(Boolean)
        lines.forEach(line => {
            const match = line.match(/(.+):(\d+):(.+)/)
            if (match) {
                const [, file, line] = match
                broadcast(id, 'update', {
                    ok: false,
                    file,
                    line: parseInt(line)
                })
            }
        })
    }

    const child = spawn('rg',
        ['-a', '-x', '-n', '--max-depth', '1', '--', password],
        {
            stdio: ['ignore', 'pipe', 'pipe'],
            cwd: `${process.cwd()}/passwords`
        }
    )

    const findChild = spawn('bash', ['./find_all.sh', password], {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: `${process.cwd()}/passwords`
    })

    child.stdout.on('data', (data: Buffer) => parseLine(data))
    child.stderr.on('data', (err: Buffer) => {
        broadcast(id, 'update', { error: err.toString() })
    })

    child.on('close', () => {
        broadcast(id, 'update', { done: true }, true)
        clientsMap.delete(id)
    })

    findChild.stdout.on('data', (data: Buffer) => parseLine(data))
    findChild.stderr.on('data', (err: Buffer) => {
        broadcast(id, 'update', { error: err.toString() })
    })

    findChild.on('close', () => {
        broadcast(id, 'update', { done: true }, true)
        clientsMap.delete(id)
    })
}
