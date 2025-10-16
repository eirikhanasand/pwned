import fp from 'fastify-plugin'
import type { FastifyInstance, FastifyRequest } from 'fastify'
import bloomWsHandler from '#utils/ws/bloomWsHandler.ts'
import broadcast, { clientsMap } from '#utils/ws/broadcast.ts'

export default fp(async function wsPlugin(fastify: FastifyInstance) {
    fastify.register(async function (fastify) {
        fastify.get('/api/bloom/ws/:id', { websocket: true }, (connection, req: FastifyRequest) => {
            const id = (req.params as { id: string}).id
            clientsMap.set(id, connection)
            broadcast(id, 'join')

            connection.once('message', (msg: string) => {
                let password: string
                try {
                    const parsed = JSON.parse(String(msg))
                    password = typeof parsed.password === 'string' ? parsed.password : String(msg)
                } catch {
                    password = String(msg)
                }

                bloomWsHandler(id, password)
            })
        })
    })
})
