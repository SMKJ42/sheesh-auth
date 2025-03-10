use std::error;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{harness::DbHarnessSession, session::Session};

use super::map_sql_result;

pub struct SqliteHarnessSession<'a> {
    connection: &'a Pool<SqliteConnectionManager>,
}

impl<'a> SqliteHarnessSession<'a> {
    pub fn new(pool: &'a Pool<SqliteConnectionManager>) -> Self {
        Self { connection: pool }
    }
}

impl<'a> DbHarnessSession for SqliteHarnessSession<'a> {
    fn delete(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.connection
            .get()?
            .execute("DELETE FROM sessions WHERE id = ?", [id])?;
        return Ok(());
    }
    fn insert(&self, session: &Session) -> Result<(), Box<dyn error::Error>> {
        println!("{:?}", session);

        self.connection.get()?.execute(
            "INSERT INTO sessions (id, user_id, refresh_token, access_token) VALUES (:id, :user_id, :refresh_token, :access_token)",
            named_params![
                ":id": session.id(),
                ":user_id": session.user_id(),
                ":refresh_token": session.refresh_token(),
                ":access_token": session.access_token(),
            ],
        )?;
        return Ok(());
    }
    fn read_by_id(&self, id: i64) -> Result<Option<Session>, Box<dyn error::Error>> {
        let connection = self.connection.get()?;
        let res = connection.query_row(
            "SELECT * FROM sessions WHERE id = :id",
            named_params! {":id": id},
            |row| {
                let user_id = row.get(1)?;
                let refresh_token = row.get(2)?;
                let access_token = row.get(3)?;
                return Ok(Session::from_values(
                    id,
                    user_id,
                    refresh_token,
                    access_token,
                ));
            },
        );

        return map_sql_result(res);
    }

    fn read_by_user_id(&self, id: i64) -> Result<Option<Session>, Box<dyn error::Error>> {
        let connection = self.connection.get()?;
        let res = connection.query_row(
            "SELECT * FROM sessions WHERE user_id = :user_id",
            named_params! {":user_id": id},
            |row| {
                let user_id = row.get(1)?;
                let refresh_token = row.get(2)?;
                let access_token = row.get(3)?;
                return Ok(Session::from_values(
                    id,
                    user_id,
                    refresh_token,
                    access_token,
                ));
            },
        );

        return map_sql_result(res);
    }
    fn update(&self, session: &Session) -> Result<(), Box<dyn error::Error>> {
        let connection = self.connection.get()?;

        connection.execute(
            "UPDATE sessions 
                SET refresh_token = :refresh_token, access_token = :access_token
                WHERE id = :id",
            named_params![
                ":refresh_token": session.refresh_token(),
                ":access_token": session.access_token(),
                ":id": session.id()
            ],
        )?;

        return Ok(());
    }

    fn create_table(&self) -> Result<(), Box<dyn error::Error>> {
        let connection = self.connection.get()?;
        connection.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    refresh_token INTEGER NOT NULL UNIQUE,
                    access_token INTEGER NOT NULL UNIQUE,
                    FOREIGN KEY(user_id) REFERENCES user(id),
                    FOREIGN KEY(refresh_token) REFERENCES refresh_tokens(id),
                    FOREIGN KEY(access_token) REFERENCES access_tokens(id)
            );",
            [],
        )?;

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_id ON sessions(user_id);",
            [],
        )?;
        return Ok(());
    }
}
