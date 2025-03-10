use std::{error, result};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{harness::DbHarnessUser, user::UserData};

use super::map_sql_result;

pub struct SqliteHarnessUser<'a> {
    connection: &'a Pool<SqliteConnectionManager>,
}

impl<'a> SqliteHarnessUser<'a> {
    pub fn new(pool: &'a Pool<SqliteConnectionManager>) -> Self {
        Self { connection: pool }
    }
}

impl<'a> DbHarnessUser for SqliteHarnessUser<'a> {
    fn delete(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.connection
            .get()?
            .prepare("DELETE FROM users WHERE id = ?")?
            .execute([id])?;
        return Ok(());
    }

    fn insert(&self, user: &UserData) -> Result<(), Box<dyn error::Error>> {
        self.connection.get()?.execute(
            "INSERT INTO users (id, session_id, username, salted_hash, ban, groups, role)
                    VALUES (:id, :session_id, :username, :salted_hash, :ban, :groups, :role)",
            named_params! {
                ":id": user.id(),
                ":session_id": user.session_id(),
                ":username": user.username(),
                ":salted_hash": user.salted_hash(),
                ":ban": user.is_banned(),
                ":groups": user.groups(),
                ":role": user.role()
            },
        )?;

        return Ok(());
    }
    fn read_by_id(&self, id: i64) -> Result<Option<UserData>, Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        let res = conn.query_row("SELECT * FROM users WHERE id = ?", [id], |row| {
            let id = row.get(0)?;
            let session_id = row.get(1)?;
            let username = row.get(2)?;
            let salted_hash = row.get(3)?;
            let ban = row.get(4)?;
            let groups = row.get(5)?;
            let role = row.get(6)?;

            return Ok(UserData::from_values(
                id,
                session_id,
                username,
                salted_hash,
                ban,
                groups,
                role,
            ));
        });

        return map_sql_result(res);
    }

    fn read_by_username(&self, username: &str) -> Result<Option<UserData>, Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        let res = conn.query_row(
            "SELECT * FROM users WHERE username = ?",
            [username],
            |row| {
                let id = row.get(0)?;
                let session_id = row.get(1)?;
                let username = row.get(2)?;
                let salted_hash = row.get(3)?;
                let ban = row.get(4)?;
                let groups = row.get(5)?;
                let role = row.get(6)?;

                return Ok(UserData::from_values(
                    id,
                    session_id,
                    username,
                    salted_hash,
                    ban,
                    groups,
                    role,
                ));
            },
        );

        return map_sql_result(res);
    }

    fn update(&self, user: &UserData) -> Result<(), Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        let res = conn.execute(
            "UPDATE users SET 
        session_id = :session_id,
        groups = :groups,
        role = :role
        WHERE id = :id",
            named_params! {
                ":session_id": user.session_id(),
                ":groups": user.groups(),
                ":role": user.role(),
                ":id": user.id(),
            },
        );

        match res {
            Ok(res) => {
                // ensure that we did not update more than one user.
                debug_assert!(res <= 1);
                return Ok(());
            }
            Err(err) => Err(err.into()),
        }
    }

    fn create_table(&self) -> result::Result<(), Box<dyn error::Error>> {
        // TODO: the FK should not exist if the session is "stateless..."
        let default_stmt = "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                session_id INTEGER,
                username STRING NOT NULL UNIQUE,
                salted_hash STRING NOT NULL,
                ban TINYINT NOT NULL,
                groups STRING NOT NULL,
                role STRING NOT NULL,
                
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            );";

        self.connection.get()?.prepare(default_stmt)?.execute([])?;

        return Ok(());
    }

    fn update_session_id(
        &self,
        user_id: i64,
        session_id: Option<i64>,
    ) -> Result<(), Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        conn.execute(
            "UPDATE users SET 
        session_id = :session_id,
        WHERE id = :id",
            named_params! {
                ":session_id": session_id,
                ":id": user_id,
            },
        )?;

        return Ok(());
    }

    fn update_salted_hash(
        &self,
        id: i64,
        salted_hash: String,
    ) -> Result<(), Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        conn.execute(
            "UPDATE users SET 
        salted_hash = :salted_hash,
        WHERE id = :id",
            named_params! {
                ":salted_hash": salted_hash,
                ":id": id,
            },
        )?;

        return Ok(());
    }

    fn update_ban(&self, id: i64, bool: bool) -> Result<(), Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        conn.execute(
            "UPDATE users SET 
        ban = :ban,
        WHERE id = :id",
            named_params! {
                ":ban": bool,
                ":id": id,
            },
        )?;

        return Ok(());
    }
}
