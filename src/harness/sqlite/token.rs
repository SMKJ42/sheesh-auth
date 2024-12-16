use std::error;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{
    auth_token::{AuthToken, TokenType},
    harness::DbHarnessToken,
};

pub struct SqliteHarnessToken {
    connection: Pool<SqliteConnectionManager>,
}

impl SqliteHarnessToken {
    pub fn new(connection: Pool<SqliteConnectionManager>) -> Self {
        Self { connection }
    }
}

impl DbHarnessToken for SqliteHarnessToken {
    fn delete_access_token(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.connection
            .get()?
            .execute("DELETE FROM access_tokens WHERE id = ?", [id])?;
        return Ok(());
    }

    fn delete_resfresh_token(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.connection
            .get()?
            .execute("DELETE FROM refresh_tokens WHERE id = ?", [id])?;
        return Ok(());
    }

    fn insert(&self, auth_token: &AuthToken) -> Result<(), Box<dyn error::Error>> {
        let connection = self.connection.get()?;
        match &auth_token.token_type() {
            TokenType::Refresh { secret } => connection.execute(
                "INSERT INTO refresh_tokens (id, user_id, secret, expires, valid)
                    VALUES (:id, :user_id, :secret, :expires, :valid",
                named_params! {
                    ":id": auth_token.id(),
                    ":user_id": auth_token.user_id(),
                    ":secret": secret,
                    ":expires": auth_token.expires(),
                    ":valid": auth_token.is_valid(),
                },
            )?,
            TokenType::Access { token } => connection.execute(
                "INSERT INTO access_tokens (id, user_id, token, expires, valid) 
                    VALUES (:id, :user_id, :token, :expires, :valid",
                named_params! {
                    ":id": auth_token.id(),
                    ":user_id": auth_token.user_id(),
                    ":secret": token,
                    ":expires": auth_token.expires(),
                    ":valid": auth_token.is_valid(),
                },
            )?,
        };

        Ok(())
    }

    fn update(&self, auth_token: &AuthToken) -> Result<(), Box<dyn error::Error>> {
        let connection = self.connection.get()?;

        match auth_token.token_type() {
            TokenType::Refresh { .. } => connection.execute(
                "UPDATE refresh_tokens
                    SET valid = :valid
                    WHERE id = :id",
                named_params! {
                    ":valid": auth_token.is_valid(),
                    ":id": auth_token.id(),
                },
            )?,
            TokenType::Access { .. } => connection.execute(
                "UPDATE access_tokens
                    SET valid = :valid,
                    WHERE id = :id",
                named_params! {
                    ":valid": auth_token.is_valid(),
                    ":id": auth_token.id(),
                },
            )?,
        };

        return Ok(());
    }

    fn create_table(&self) -> Result<(), Box<dyn error::Error>> {
        let connection = self.connection.get()?;

        connection.execute(
            "CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    secret STRING NOT NULL,
                    expires DATETIME NOT NULL,
                    valid BOOL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
            );",
            [],
        )?;
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_id ON refresh_tokens(user_id);",
            [],
        )?;

        connection.execute(
            "CREATE TABLE IF NOT EXISTS access_tokens (
                    id INTEGER PRIMARY KEY NOT NULL,
                    user_id INTEGER NOT NULL,
                    token STRING NOT NULL,
                    expires DATETIME NOT NULL,
                    valid BOOL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
            );",
            [],
        )?;

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_id ON access_tokens(user_id);",
            [],
        )?;
        return Ok(());
    }

    fn read_access_token(&self, id: i64) -> Result<Option<AuthToken>, Box<dyn error::Error>> {
        let connection = self.connection.get()?;

        match connection.query_row(
            "SELECT * FROM access_tokens WHERE id = :id;",
            named_params! {":id": id},
            |row| {
                let user_id = row.get(1)?;
                let token_type = TokenType::Access { token: row.get(2)? };
                let expires = row.get(3)?;
                let valid = row.get(4)?;
                return Ok(AuthToken::from_values(
                    id, user_id, token_type, expires, valid,
                ));
            },
        ) {
            Ok(token) => return Ok(Some(token)),
            Err(err) => return Err(err.into()),
        }
    }

    fn read_refresh_token(&self, id: i64) -> Result<Option<AuthToken>, Box<dyn error::Error>> {
        let connection = self.connection.get()?;

        match connection.query_row(
            "SELECT * FROM refresh_tokens WHERE id = :id;",
            named_params! {":id": id},
            |row| {
                let user_id = row.get(1)?;
                let token_type = TokenType::Refresh {
                    secret: row.get(2)?,
                };
                let expires = row.get(3)?;
                let valid = row.get(4)?;
                return Ok(AuthToken::from_values(
                    id, user_id, token_type, expires, valid,
                ));
            },
        ) {
            Ok(token) => return Ok(Some(token)),
            Err(err) => return Err(err.into()),
        }
    }
}
