import cors from '@fastify/cors'
import Fastify from 'fastify'
import routes from './routes.ts'
import getIndex from './handlers/index/get.ts'
import websocketPlugin from '@fastify/websocket'
// import buildBloomPerFile from '#utils/buildBloom.ts'
import ws from './plugins/ws.ts'
import { getPasswordIndexStatus } from '#utils/passwordIndex.ts'

const fastify = Fastify({
    logger: true
})

fastify.register(websocketPlugin)
fastify.register(cors, {
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']
})

const port = Number(process.env.PORT) || 8080

fastify.register(ws, { prefix: '/api' })
fastify.register(routes, { prefix: '/api' })
fastify.get('/', getIndex)

async function start() {
    try {
        await fastify.listen({ port, host: '0.0.0.0' })
    } catch (err) {
        fastify.log.error(err)
        process.exit(1)
    }
}

async function main() {
    // buildBloomPerFile().catch(console.error)
    void getPasswordIndexStatus()
        .then(status => fastify.log.info({ passwordIndex: status }, 'Password index warmed'))
        .catch(error => fastify.log.error(error, 'Failed to warm password index'))
    start()
}

main()
