import { WebSocket as WS } from 'ws'
import { shareClients } from './handleMessage.ts'

export function removeClient(shareId: string, socket: WS) {
    const clients = shareClients.get(shareId)
    if (!clients) {
        return
    }

    clients.delete(socket)
    if (clients.size === 0) {
        shareClients.delete(shareId)
    }
}
