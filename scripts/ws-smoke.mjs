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

        const localOnlyResponse = await fetch(`http://127.0.0.1:${port}/api/pwned`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: 'codex-local-only-lookup-proof' })
        })
        const localOnlyResult = await localOnlyResponse.json()
        if (localOnlyResult.ok !== false || localOnlyResult.count !== 0) {
            throw new Error(`Expected local-only sorted master hit to make /pwned fail, got ${JSON.stringify(localOnlyResult)}`)
        }

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

        if ('match' in match) {
            throw new Error(`Expected sorted websocket result to omit password text, got ${JSON.stringify(match)}`)
        }

        if (typeof match.offset !== 'number') {
            throw new Error(`Expected sorted websocket result to include byte offset, got ${JSON.stringify(match)}`)
        }

        if (messages.some(message => message.match === 'Eirik2002123')) {
            throw new Error(`Expected exact matching only, got prefix result ${JSON.stringify(messages)}`)
        }

        const localOnlyMessages = await new Promise((resolve, reject) => {
            const ws = new WebSocket(wsUrl)
            const received = []

            ws.on('open', () => {
                ws.send(JSON.stringify({ password: 'codex-local-only-lookup-proof' }))
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

        if (!localOnlyMessages.some(message => message.file?.endsWith('all_in_one_sorted.txt'))) {
            throw new Error(`Expected websocket local-only search to find sorted master, got ${JSON.stringify(localOnlyMessages)}`)
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
