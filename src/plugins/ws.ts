import fp from 'fastify-plugin'
import type { FastifyInstance, FastifyRequest } from 'fastify'
import { registerClient } from '#utils/ws/registerClient.ts'
import { handleMessage } from '#utils/ws/handleMessage.ts'
import { removeClient } from '#utils/ws/removeClient.ts'

export default fp(async function wsSharePlugin(fastify: FastifyInstance) {
    fastify.register(async function (fastify) {
        fastify.get('/api/share/ws/:id', { websocket: true }, (connection, req: FastifyRequest) => {
            const id = (req.params as { id: string}).id

            registerClient(id, connection)
            connection.on('message', message => {
                handleMessage(id, connection, message)
            })

            connection.on('close', () => {
                removeClient(id, connection)
            })
        })
    })
})
