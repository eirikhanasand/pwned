import type { FastifyInstance, FastifyPluginOptions } from "fastify"
import getIndex from './handlers/index/get.ts'
import getFile from './handlers/files/get.ts'
import putFile from './handlers/files/put.ts'
import postFile from './handlers/files/post.ts'
import deleteFile from './handlers/files/delete.ts'
import getFileByPath from './handlers/files/getByPath.ts'
import getShare from './handlers/share/get.ts'
import putShare from './handlers/share/put.ts'
import postShare from './handlers/share/post.ts'

export default async function apiRoutes(fastify: FastifyInstance, _: FastifyPluginOptions) {
    // index
    fastify.get("/", getIndex)

    // files
    fastify.get("/files/:id", getFile)
    fastify.get("/files/path/:id", getFileByPath)
    fastify.put("/files/:id", putFile)
    fastify.post("/files/:id", postFile)
    fastify.delete("/files/:id", deleteFile)

    // share
    fastify.get("/share/:id", getShare)
    fastify.put("/share/:id", putShare)
    fastify.post("/share/:id", postShare)
}
