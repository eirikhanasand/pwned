import { WebSocket } from 'ws'
import { shareClients } from './handleMessage.ts'
import { WebSocket as WS } from 'ws'

export function registerClient(id: string, socket: WebSocket) {
    if (!shareClients.has(id)) {
        shareClients.set(id, new Set())
    }

    shareClients.get(id)!.add(socket)
    broadcastJoin(id)
}

function broadcastJoin(id: string) {
    const clients = shareClients.get(id)
    if (!clients) {
        return
    }

    const payload = JSON.stringify({
        type: 'join',
        timestamp: new Date().toISOString(),
        participants: clients.size
    })

    for (const client of clients) {
        if (client.readyState === WS.OPEN) {
            client.send(payload)
        }
    }
}
