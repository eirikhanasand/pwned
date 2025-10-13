import { WebSocket } from 'ws'
import { shareClients } from './handleMessage.ts'

export function registerClient(shareId: string, socket: WebSocket) {
    if (!shareClients.has(shareId)) {
        shareClients.set(shareId, new Set())
    }

    shareClients.get(shareId)!.add(socket)
}
