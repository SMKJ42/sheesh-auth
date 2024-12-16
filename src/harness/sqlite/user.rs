use std::{error, result};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{
    harness::DbHarnessUser,
    user::{PrivateUserMeta, PublicUserMeta, UserMeta},
};

pub struct SqliteHarnessUser {
    connection: Pool<SqliteConnectionManager>,
    private_cols: Vec<&'static str>,
    public_cols: Vec<&'static str>,
}

impl SqliteHarnessUser {
    pub fn new(connection: Pool<SqliteConnectionManager>) -> Self {
        Self {
            connection,
            private_cols: Vec::new(),
            public_cols: Vec::new(),
        }
    }

    pub fn with_public_cols(mut self, cols: Vec<&'static str>) -> Self {
        self.public_cols = cols;
        return self;
    }

    pub fn with_private_cols(mut self, cols: Vec<&'static str>) -> Self {
        self.private_cols = cols;
        return self;
    }
}

impl DbHarnessUser for SqliteHarnessUser {
    fn delete(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.connection
            .get()?
            .prepare("DELETE FROM users WHERE id = ?")?
            .execute([id])?;
        return Ok(());
    }

    fn insert(&self, user: &UserMeta) -> Result<(), Box<dyn error::Error>> {
        //TODO: dynamically utilize the fields in the .public_meta and .private_meta
        self.connection.get()?.execute(
            "INSERT INTO users (id, session_id, username, secret, ban, groups, role)
                    VALUES (:id, :session_id, :username, :secret, :ban, :groups, :role)",
            named_params! {
                ":id": user.id(),
                ":session_id": user.session_id(),
                ":username": user.username(),
                ":secret": user.secret(),
                ":ban": user.is_banned(),
                ":groups": user.groups(),
                ":role": user.role()
            },
        )?;

        return Ok(());
    }
    fn read_by_id(&self, id: i64) -> Result<Option<UserMeta>, Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        let res = conn.query_row("SELECT * FROM users WHERE id = ?", [id], |row| {
            let id = row.get(0)?;
            let session_id = row.get(1)?;
            let username = row.get(2)?;
            let secret = row.get(3)?;
            let ban = row.get(4)?;
            let groups = row.get(5)?;
            let role = row.get(6)?;

            return Ok(UserMeta::from_values(
                id, session_id, username, secret, ban, groups, role,
            ));
        });

        match res {
            Ok(user) => Ok(Some(user)),
            Err(err) => Err(err.into()),
        }
    }

    fn read_by_username(&self, username: &str) -> Result<Option<UserMeta>, Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        let res = conn.query_row(
            "SELECT * FROM users WHERE username = ?",
            [username],
            |row| {
                let id = row.get(0)?;
                let session_id = row.get(1)?;
                let username = row.get(2)?;
                let secret = row.get(3)?;
                let ban = row.get(4)?;
                let groups = row.get(5)?;
                let role = row.get(6)?;

                return Ok(UserMeta::from_values(
                    id, session_id, username, secret, ban, groups, role,
                ));
            },
        );

        match res {
            Ok(user) => Ok(Some(user)),
            Err(err) => Err(err.into()),
        }
    }

    fn update(&self, user: &UserMeta) -> Result<(), Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        let res = conn.execute(
            "UPDATE users SET 
        session_id = :session_id,
        username = :username,
        ban = :ban,
        groups = :groups,
        role = :role
        WHERE id = :id",
            named_params! {
                ":session_id": user.session_id(),
                ":username": user.username(),
                ":ban": user.is_banned(),
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
        let default_stmt = "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username STRING NOT NULL UNIQUE,
                secret STRING NOT NULL,
                ban TINYINT NOT NULL,
                groups STRING NOT NULL,
                role STRING NOT NULL,
                session_id INTEGER,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            );";

        self.connection.get()?.prepare(default_stmt)?.execute([])?;

        return Ok(());
    }
    fn set_ban(&self, id: i64, bool: bool) -> Result<(), Box<dyn error::Error>> {
        let conn = self.connection.get()?;
        let res = conn.execute(
            "UPDATE users SET 
        ban = :ban,
        WHERE id = :id",
            named_params! {
                ":ban": bool,
                ":id": id,
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
}
