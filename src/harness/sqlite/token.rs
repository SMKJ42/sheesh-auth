use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{
    auth_token::{AuthToken, TokenType},
    harness::{harness_error, DbHarnessToken, HarnessError},
};

use super::map_sql_result;

pub struct SqliteHarnessToken {
    connection: Pool<SqliteConnectionManager>,
}

impl SqliteHarnessToken {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { connection: pool }
    }
}

impl DbHarnessToken for SqliteHarnessToken {
    fn delete_access_token(&self, id: i64) -> Result<(), HarnessError> {
        self.connection
            .get()
            .map_err(harness_error)?
            .execute("DELETE FROM access_tokens WHERE id = ?", [id])
            .map_err(harness_error)?;
        return Ok(());
    }

    fn delete_access_token_by_session(&self, session_id: i64) -> Result<(), HarnessError> {
        self.connection
            .get()
            .map_err(harness_error)?
            .execute(
                "DELETE FROM access_tokens WHERE session_id = ?",
                [session_id],
            )
            .map_err(harness_error)?;
        return Ok(());
    }

    fn delete_resfresh_token(&self, id: i64) -> Result<(), HarnessError> {
        self.connection
            .get()
            .map_err(harness_error)?
            .execute("DELETE FROM refresh_tokens WHERE id = ?", [id])
            .map_err(harness_error)?;
        return Ok(());
    }

    fn delete_refresh_token_by_session(&self, session_id: i64) -> Result<(), HarnessError> {
        self.connection
            .get()
            .map_err(harness_error)?
            .execute(
                "DELETE FROM refresh_tokens WHERE session_id = ?",
                [session_id],
            )
            .map_err(harness_error)?;
        return Ok(());
    }

    fn insert(&self, auth_token: &AuthToken) -> Result<(), HarnessError> {
        let connection = self.connection.get().map_err(harness_error)?;
        match &auth_token.token_type() {
            TokenType::Refresh => connection
                .execute(
                    "INSERT INTO refresh_tokens (id, session_id, salted_hash, expires, valid)
                    VALUES (:id, :session_id, :salted_hash, :expires, :valid)",
                    named_params! {
                        ":id": auth_token.id(),
                        ":session_id": auth_token.session_id(),
                        ":salted_hash": auth_token.salted_hash(),
                        ":expires": auth_token.expires(),
                        ":valid": true,
                    },
                )
                .map_err(harness_error)?,
            TokenType::Access => connection
                .execute(
                    "INSERT INTO access_tokens (id, session_id, salted_hash, expires, valid)
                    VALUES (:id, :session_id, :salted_hash, :expires, :valid)",
                    named_params! {
                        ":id": auth_token.id(),
                        ":session_id": auth_token.session_id(),
                        ":salted_hash": auth_token.salted_hash(),
                        ":expires": auth_token.expires(),
                        ":valid": true,
                    },
                )
                .map_err(harness_error)?,
        };

        Ok(())
    }

    fn create_table(&self) -> Result<(), HarnessError> {
        let connection = self.connection.get().map_err(harness_error)?;

        connection
            .execute(CREATE_REFRESH_TABLE_STATEMENT, [])
            .map_err(harness_error)?;
        connection
            .execute(CREATE_ACCESS_TABLE_STATEMENT, [])
            .map_err(harness_error)?;

        return Ok(());
    }

    fn read_access_token(&self, session_id: i64) -> Result<Option<AuthToken>, HarnessError> {
        let connection = self.connection.get().map_err(harness_error)?;

        let res = connection.query_row(
            "SELECT * FROM access_tokens WHERE session_id = :session_id;",
            named_params! {":session_id": session_id},
            |row| {
                let user_id = row.get(1)?;
                let salted_hash = row.get(2)?;
                let token_type = TokenType::Access;
                let expires = row.get(3)?;
                return Ok(AuthToken::from_values(
                    session_id,
                    user_id,
                    salted_hash,
                    token_type,
                    expires,
                ));
            },
        );

        return map_sql_result(res);
    }

    fn read_refresh_token(&self, session_id: i64) -> Result<Option<AuthToken>, HarnessError> {
        let connection = self.connection.get().map_err(harness_error)?;

        let res = connection.query_row(
            "SELECT * FROM refresh_tokens WHERE session_id = :session_id;",
            named_params! {":session_id": session_id},
            |row| {
                let user_id = row.get(1)?;
                let salted_hash = row.get(2)?;
                let token_type = TokenType::Refresh;
                let expires = row.get(3)?;
                return Ok(AuthToken::from_values(
                    session_id,
                    user_id,
                    salted_hash,
                    token_type,
                    expires,
                ));
            },
        );

        return map_sql_result(res);
    }
}

const CREATE_REFRESH_TABLE_STATEMENT: &'static str = "CREATE TABLE refresh_tokens (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL,
    salted_hash TEXT NOT NULL,
    expires DATETIME NOT NULL,
    valid BOOLEAN NOT NULL CHECK (valid IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_id ON refresh_tokens(session_id);";

const CREATE_ACCESS_TABLE_STATEMENT: &'static str = "CREATE TABLE access_tokens (
    id INTEGER PRIMARY KEY NOT NULL,
    session_id INTEGER NOT NULL,
    salted_hash TEXT NOT NULL,
    expires DATETIME NOT NULL,
    valid BOOLEAN NOT NULL CHECK (valid IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_id ON access_tokens(session_id);";
