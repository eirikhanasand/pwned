import type { FastifyInstance, FastifyPluginOptions } from "fastify"
import getIndex from './handlers/index/get.ts'

export default async function apiRoutes(fastify: FastifyInstance, _: FastifyPluginOptions) {
    // index
    fastify.get("/", getIndex)
}
