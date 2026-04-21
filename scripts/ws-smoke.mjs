import { spawn } from 'child_process'
import path from 'path'
import process from 'process'
import { setTimeout as delay } from 'timers/promises'
import WebSocket from 'ws'

const repoDir = process.cwd()
const fixturePasswords = path.join(repoDir, 'tests', 'fixtures', 'passwords')
const port = Number(process.env.PORT || 18252)
const apiUrl = `http://127.0.0.1:${port}/api/passwords/status`
const wsUrl = `ws://127.0.0.1:${port}/api/pwned/ws/smoke`

async function waitForServer() {
    for (let attempt = 0; attempt < 50; attempt += 1) {
        try {
            const response = await fetch(apiUrl)
            if (response.ok) {
                return
            }
        } catch {}

        await delay(200)
    }

    throw new Error(`Server did not become ready at ${apiUrl}`)
}

async function runSmoke() {
    const child = spawn('bun', ['src/index.ts'], {
        cwd: repoDir,
        env: {
            ...process.env,
            PORT: String(port),
            PASSWORDS_DIR: fixturePasswords,
            PASSWORD_AUDIT_INTERVAL_MS: '600000'
        },
        stdio: ['ignore', 'inherit', 'inherit']
    })

    try {
        await waitForServer()

        const messages = await new Promise((resolve, reject) => {
            const ws = new WebSocket(wsUrl)
            const received = []

            ws.on('open', () => {
                ws.send(JSON.stringify({ password: 'Eirik2002' }))
            })

            ws.on('message', message => {
                const parsed = JSON.parse(String(message))
                received.push(parsed)
                if (parsed.done) {
                    ws.close()
                    resolve(received)
                }
            })

            ws.on('error', reject)
        })

        const match = messages.find(message => message.file?.endsWith('all_in_one_sorted.txt'))
        if (!match) {
            throw new Error(`Expected websocket smoke test to find all_in_one_sorted.txt, got ${JSON.stringify(messages)}`)
        }
    } finally {
        child.kill('SIGTERM')
        await delay(200)
    }
}

runSmoke().catch(error => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(1)
})
