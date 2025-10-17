import type { FastifyReply, FastifyRequest } from "fastify"

/**
 * Base information about the pwned API if the route was not specified
 * @param req FastifyRequest, used to fetch the valid routes
 * @param res FastifyReply, used to send the response to the user
 */
export default async function getIndex(req: FastifyRequest, res: FastifyReply) {
    const routes = req.server.printRoutes({ commonPrefix: false })
    res.send(`pwned.\n\nValid endpoints are:\n\n${routes}`)
}
