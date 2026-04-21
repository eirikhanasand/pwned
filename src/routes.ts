import type { FastifyInstance, FastifyPluginOptions } from "fastify"
import getIndex from './handlers/index/get.ts'
import pwnedHandler from './handlers/pwned/post.ts'
import { getPasswordIndexStatus } from '#utils/passwordIndex.ts'
import { getLatestPasswordAudit } from '#utils/passwordAudit.ts'

export default async function apiRoutes(fastify: FastifyInstance, _: FastifyPluginOptions) {
    // index
    fastify.get("/", getIndex)

    // pwned
    fastify.post("/pwned", pwnedHandler)
    fastify.get("/passwords/status", async () => ({
        index: await getPasswordIndexStatus(),
        audit: getLatestPasswordAudit()
    }))
}
