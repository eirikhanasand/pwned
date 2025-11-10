import { spawn } from 'child_process'
import broadcast, { clientsMap } from './broadcast.ts'

export default function execPipeAndBroadcast(id: string, password: string): void {
  // Track leftover buffers per stream
  let childLeftover = ''
  let findLeftover = ''
  let remaining = 2 // number of processes to wait for

  // Helper to parse lines from any stream
  function parseLine(data: Buffer, isFind: boolean) {
    let leftover = isFind ? findLeftover : childLeftover
    const text = leftover + data.toString()
    const lines = text.split('\n')
    leftover = lines.pop() || '' // keep incomplete line

    lines.forEach(rawLine => {
      const line = rawLine.trim()
      if (!line) return

      // Matches "file:line" or "file:line:match"
      const match = line.match(/^(.+):(\d+)(?::(.*))?$/)
      if (match) {
        const [, file, lineNum, matchText] = match
        broadcast(id, 'update', {
          ok: false,
          file,
          line: parseInt(lineNum, 10),
          ...(matchText ? { match: matchText } : {})
        })
      }
    })

    if (isFind) findLeftover = leftover
    else childLeftover = leftover
  }

  // Spawn ripgrep
  const child = spawn('rg', ['-a', '-x', '-n', '--max-depth', '1', '--', password], {
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: `${process.cwd()}/passwords`
  })

  // Spawn find_all.sh
  const findChild = spawn('sh', ['./find_all.sh', password], {
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: `${process.cwd()}/passwords`
  })

  // Attach stdout handlers
  child.stdout.on('data', (data: Buffer) => parseLine(data, false))
  findChild.stdout.on('data', (data: Buffer) => parseLine(data, true))

  // Attach stderr handlers
  child.stderr.on('data', (err: Buffer) => {
    broadcast(id, 'update', { error: err.toString() })
  })
  findChild.stderr.on('data', (err: Buffer) => {
    broadcast(id, 'update', { error: err.toString() })
  })

  // Close handler for both processes
  function onChildClose() {
    remaining -= 1
    if (remaining <= 0) {
      // flush any leftover line
      if (childLeftover) parseLine(Buffer.from(''), false)
      if (findLeftover) parseLine(Buffer.from(''), true)

      broadcast(id, 'update', { done: true }, true)
      clientsMap.delete(id)
    }
  }

  child.on('close', onChildClose)
  findChild.on('close', onChildClose)
}
