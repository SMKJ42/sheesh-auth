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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP

);

CREATE INDEX IF NOT EXISTS idx_username ON users(username);

## Session

CREATE TABLE sessions (

    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    <!-- TODO: App logic -->
    ip_addr TEXT,
    <!-- TODO: App logic -->
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP

    <!--
        expiry should be nullable here.
         - session expiry allows for refresh tokens to be limited to a fixed
           timeline instead of a fixed # of refreshes.
         - Nullable allows the implementor to opt-out of this behavior and rely
           on refresh token logic to keep the session valid.
    -->
    <!-- TODO: App logic -->
    expires DATETIME

    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,

);

CREATE INDEX IF NOT EXISTS idx_user_id ON sessions(user_id);

## Refresh Token

CREATE TABLE refresh_tokens (

    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL,
    salted_hash TEXT NOT NULL,
    expires DATETIME NOT NULL,

    <!-- TODO: App logic -->
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE

);

CREATE INDEX IF NOT EXISTS idx_session_id ON refresh_tokens(session_id);

## Access Token

CREATE TABLE access_tokens (

    id INTEGER PRIMARY KEY NOT NULL,
    session_id INTEGER NOT NULL,
    salted_hash TEXT NOT NULL,
    expires DATETIME NOT NULL,

    <!-- TODO: App logic -->
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE

);

CREATE INDEX IF NOT EXISTS idx_session_id ON access_tokens(session_id);
