DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cdn') THEN
        CREATE DATABASE "cdn";
    END IF;
END $$;

\c "cdn"

DO $$
DECLARE
    user_password text;
BEGIN
    user_password := current_setting('db_password', true);

    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cdn') THEN
        EXECUTE format('CREATE USER "cdn" WITH ENCRYPTED PASSWORD %L', user_password);
        EXECUTE 'GRANT ALL PRIVILEGES ON DATABASE "cdn" TO "cdn"';
    END IF;
END $$;

-- Files
CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    data BYTEA NOT NULL,
    type TEXT NOT NULL,
    path TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ DEFAULT NOW()
);

-- Shares
CREATE TABLE IF NOT EXISTS shares (
    id SERIAL PRIMARY KEY,
    path TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_shares_path ON shares(path);
CREATE UNIQUE INDEX IF NOT EXISTS idx_images_name ON images(name);
