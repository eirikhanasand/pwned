import { WebSocket as WS } from 'ws'

export const clientsMap = new Map<string, WS>()

export default function broadcast(id: string, type: string, content?: object, close?: boolean) {
    const client = clientsMap.get(id)
    if (!client) {
        return
    }

    const base = { type, timestamp: new Date().toISOString() }
    const payload = JSON.stringify(content ? { ...base, ...content } : { ...base })

    if (client.readyState === WS.OPEN) {
        client.send(payload)
    }

    if (close) {
        client.close()
    }
}
