use std::result;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{
    harness::{harness_error, DbHarnessUser, DbHarnessUserExt, HarnessError},
    user::UserData,
};

use super::map_sql_result;

pub struct SqliteHarnessUser {
    connection: Pool<SqliteConnectionManager>,
}

impl SqliteHarnessUser {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { connection: pool }
    }
}

impl<'a> DbHarnessUser for SqliteHarnessUser {
    fn delete(&self, id: i64) -> Result<(), HarnessError> {
        self.connection
            .get()
            .map_err(harness_error)?
            .prepare("DELETE FROM users WHERE id = ?")
            .map_err(harness_error)?
            .execute([id])
            .map_err(harness_error)?;
        return Ok(());
    }

    fn insert(&self, user: &UserData) -> Result<(), HarnessError> {
        self.connection.get().map_err(harness_error)?.execute(
            "INSERT INTO users (id, username, salted_hash, is_banned, groups, role, failed_attempts)
                    VALUES (:id, :username, :salted_hash, :is_banned, :groups, :role, :failed_attempts)",
            named_params! {
                ":id": user.id(),
                ":username": user.username(),
                ":salted_hash": user.salted_hash(),
                ":is_banned": user.is_banned(),
                ":groups": user.groups(),
                ":role": user.role(),
                ":failed_attempts": user.failed_attempts(),
            },
        ).map_err(harness_error)?;

        return Ok(());
    }
    fn read_by_id(&self, id: i64) -> Result<Option<UserData>, HarnessError> {
        let conn = self.connection.get().map_err(harness_error)?;
        let res = conn.query_row("SELECT * FROM users WHERE id = ?", [id], |row| {
            let id = row.get(0)?;
            let username = row.get(1)?;
            let groups = row.get(2)?;
            let role = row.get(3)?;
            let failed_attempts = row.get(4)?;
            let salted_hash = row.get(5)?;
            let is_banned = row.get(6)?;

            return Ok(UserData::from_values(
                id,
                username,
                salted_hash,
                is_banned,
                groups,
                role,
                failed_attempts,
            ));
        });

        return map_sql_result(res);
    }

    fn read_by_username(&self, username: &str) -> Result<Option<UserData>, HarnessError> {
        let conn = self.connection.get().map_err(harness_error)?;
        let res = conn.query_row(
            "SELECT * FROM users WHERE username = ?",
            [username],
            |row| {
                let id = row.get(0)?;
                let username = row.get(1)?;
                let groups = row.get(2)?;
                let role = row.get(3)?;
                let failed_attempts = row.get(4)?;
                let salted_hash = row.get(5)?;
                let is_banned = row.get(6)?;

                return Ok(UserData::from_values(
                    id,
                    username,
                    salted_hash,
                    is_banned,
                    groups,
                    role,
                    failed_attempts,
                ));
            },
        );

        return map_sql_result(res);
    }

    fn update(&self, user: &UserData) -> Result<(), HarnessError> {
        let conn = self.connection.get().map_err(harness_error)?;
        let res = conn
            .execute(
                "UPDATE users SET
        groups = :groups,
        role = :role
        WHERE id = :id",
                named_params! {
                    ":groups": user.groups(),
                    ":role": user.role(),
                    ":id": user.id(),
                },
            )
            .map_err(harness_error)?;

        debug_assert!(res <= 1);
        return Ok(());
    }

    fn create_table(&self) -> result::Result<(), HarnessError> {
        self.connection
            .get()
            .map_err(harness_error)?
            .prepare(CREATE_USER_TABLE_STATEMENT)
            .map_err(harness_error)?
            .execute([])
            .map_err(harness_error)?;

        return Ok(());
    }

    fn update_salted_hash(&self, id: i64, salted_hash: &str) -> Result<(), HarnessError> {
        let conn = self.connection.get().map_err(harness_error)?;
        conn.execute(
            "UPDATE users SET
        salted_hash = :salted_hash,
        WHERE id = :id",
            named_params! {
                ":salted_hash": salted_hash,
                ":id": id,
            },
        )
        .map_err(harness_error)?;

        return Ok(());
    }
}

impl<'a> DbHarnessUserExt for SqliteHarnessUser {
    fn set_attempts(&self, id: i64, count: i64) -> Result<(), HarnessError> {
        let conn = self.connection.get().map_err(harness_error)?;

        conn.execute(
            "UPDATE users SET
        failed_attempts = :failed_attempts,
        WHERE id = :id",
            named_params! {
                ":failed_attempts": count,
                ":id": id,
            },
        )
        .map_err(harness_error)?;

        return Ok(());
    }

    fn update_username(&self, id: i64, username: &str) -> Result<(), HarnessError> {
        let conn = self.connection.get().map_err(harness_error)?;

        conn.execute(
            "UPDATE users SET
        username = :username,
        WHERE id = :id",
            named_params! {
                ":username": username,
                ":id": id,
            },
        )
        .map_err(harness_error)?;

        return Ok(());
    }

    fn set_ban(&self, id: i64, ban: bool) -> Result<(), HarnessError> {
        let conn = self.connection.get().map_err(harness_error)?;

        conn.execute(
            "UPDATE users SET
        is_banned = :is_banned,
        WHERE id = :id",
            named_params! {
                ":is_banned": ban,
                ":id": id,
            },
        )
        .map_err(harness_error)?;

        return Ok(());
    }
}

const CREATE_USER_TABLE_STATEMENT: &'static str = "CREATE TABLE users (
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

CREATE INDEX IF NOT EXISTS idx_username ON users(username);";
