import dotenv from 'dotenv'

dotenv.config()

const requiredEnvironmentVariables = [
    'DB_PASSWORD',
    'DB_HOST',
]

const missingVariables = requiredEnvironmentVariables.filter(
    (key) => !process.env[key]
)

if (missingVariables.length > 0) {
    throw new Error(
        'Missing essential environment variables:\n' +
            missingVariables
                .map((key) => `${key}: ${process.env[key] || 'undefined'}`)
                .join('\n')
    )
}

const env = Object.fromEntries(
    requiredEnvironmentVariables.map((key) => [key, process.env[key]])
)

const config = {
    DB_PORT: env.DB_PORT,
    DB_MAX_CONN: env.DB_MAX_CONN,
    DB_IDLE_TIMEOUT_MS: env.DB_IDLE_TIMEOUT_MS,
    DB_TIMEOUT_MS: env.DB_TIMEOUT_MS,
    DB: env.DB,
    DB_HOST: env.DB_HOST,
    DB_USER: env.DB_USER,
    DB_PASSWORD: env.DB_PASSWORD,
    CACHE_TTL: 30000
}

export default config
