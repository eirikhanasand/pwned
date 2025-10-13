import run from '#db'
import type { RawData } from 'ws'
import { WebSocket as WS } from 'ws'

export const shareClients = new Map<string, Set<WS>>()
export const pendingUpdates = new Map<string, { content: string; timer: NodeJS.Timeout }>()

export async function handleMessage(
    id: string,
    socket: WS,
    rawMessage: RawData,
) {
    try {
        const msg = JSON.parse(rawMessage.toString())
        if (msg.type !== 'edit') {
            return
        }

        broadcastUpdate(id, socket, msg.content)
        queueSave(id, msg.content)
    } catch (err) {
        console.error('Invalid WebSocket message:', err)
    }
}

function broadcastUpdate(id: string, sender: WS, content: string) {
    const clients = shareClients.get(id)
    if (!clients) {
        return
    }

    const payload = JSON.stringify({
        type: 'update',
        content,
        timestamp: new Date().toISOString(),
        participants: clients.size
    })

    for (const client of clients) {
        if (client !== sender && client.readyState === WS.OPEN) {
            client.send(payload)
        }
    }
}

function queueSave(id: string, content: string) {
    if (pendingUpdates.has(id)) {
        const entry = pendingUpdates.get(id)!
        entry.content = content
        clearTimeout(entry.timer)
    }

    const timer = setTimeout(async () => {
        const entry = pendingUpdates.get(id)
        if (!entry) return
        try {
            await run(
                `UPDATE share SET content = $1, timestamp = NOW() WHERE id = $2`,
                [entry.content, id]
            )
            console.log(`💾 Saved share ${id} to DB`)
        } catch (err) {
            console.error(`❌ Failed to save share ${id}:`, err)
        } finally {
            pendingUpdates.delete(id)
        }
    }, 1000)

    pendingUpdates.set(id, { content, timer })
}
