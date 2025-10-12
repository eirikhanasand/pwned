import pg from 'pg'
import config from '#constants'

type SQLParamType = (string | number | null | boolean | string[] | Date)[]

const { 
    DB, 
    DB_USER, 
    DB_HOST,
    DB_PASSWORD, 
    DB_PORT, 
    DB_MAX_CONN, 
    DB_IDLE_TIMEOUT_MS, 
    DB_TIMEOUT_MS
} = config
const { Pool } = pg
const pool = new Pool({
    user: DB_USER || "hanasand",
    host: DB_HOST,
    database: DB || "hanasand_database",
    password: DB_PASSWORD,
    port: Number(DB_PORT) || 5432,
    max: Number(DB_MAX_CONN) || 20,
    idleTimeoutMillis: Number(DB_IDLE_TIMEOUT_MS) || 5000,
    connectionTimeoutMillis: Number(DB_TIMEOUT_MS) || 3000,
    keepAlive: true
})

export default async function run(query: string, params?: SQLParamType) {
    while (true) {
        try {
            const client = await pool.connect()
            try {
                return await client.query(query, params ?? [])
            } finally {
                client.release()
            }
        } catch (error) {
            console.log(`Pool currently unavailable, retrying in ${config.CACHE_TTL / 1000}s...`)
            console.log(error)
            await sleep(config.CACHE_TTL)
        }
    }
}

function sleep(ms: number) {
    return new Promise(res => setTimeout(res, ms))
}
