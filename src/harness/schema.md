### The following values are the default SQL values when no extra fields are provided.

## User

CREATE TABLE users (

    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    groups TEXT NOT NULL,
    role TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL,
    salted_hash TEXT NOT NULL,
    is_banned BOOLEAN NOT NULL CHECK (is_banned IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP

);

CREATE INDEX IF NOT EXISTS idx_username ON users(username);

## Session

CREATE TABLE sessions (

    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    ip_addr TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires DATETIME,

    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE

);

CREATE INDEX IF NOT EXISTS idx_user_id ON sessions(user_id);

## Refresh Token

CREATE TABLE refresh_tokens (

    id INTEGER PRIMARY KEY NOT NULL,
    session_id INTEGER NOT NULL,
    salted_hash TEXT NOT NULL,
    expires DATETIME NOT NULL,
    valid BOOLEAN NOT NULL CHECK (valid IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE

);

CREATE INDEX IF NOT EXISTS idx_session_id ON access_tokens(session_id);

## Access Token

CREATE TABLE access_tokens (

    id INTEGER PRIMARY KEY NOT NULL,
    session_id INTEGER NOT NULL,
    salted_hash TEXT NOT NULL,
    expires DATETIME NOT NULL,
    valid BOOLEAN NOT NULL CHECK (valid IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE

);

CREATE INDEX IF NOT EXISTS idx_session_id ON access_tokens(session_id);
