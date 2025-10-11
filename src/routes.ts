import type { FastifyInstance, FastifyPluginOptions } from "fastify"
import getIndex from './handlers/index/get.ts'
import getFile from './handlers/files/get.ts'
import putFile from './handlers/files/putFile.ts'
import postFile from './handlers/files/post.ts'

export default async function apiRoutes(fastify: FastifyInstance, _: FastifyPluginOptions) {
    // index
    fastify.get("/", getIndex)
    
    // files
    fastify.get("files/", getFile)
    fastify.put("files/:id", putFile)
    fastify.post("files/:id", postFile)
}
