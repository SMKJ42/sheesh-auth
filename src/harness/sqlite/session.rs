use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{
    harness::{harness_error, DbHarnessSession, HarnessError},
    session::Session,
};

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
    fn delete(&self, id: i64) -> Result<(), HarnessError> {
        self.connection
            .get()
            .map_err(harness_error)?
            .execute("DELETE FROM sessions WHERE id = ?", [id])
            .map_err(harness_error)?;
        return Ok(());
    }
    fn insert(&self, session: &Session) -> Result<(), HarnessError> {
        let ip_str = if let Some(ip_addr) = session.ip_addr() {
            Some(ip_addr.to_string())
        } else {
            None
        };

        self.connection
            .get()
            .map_err(harness_error)?
            .execute(
                "INSERT INTO sessions (id, user_id, ip_addr, created_at, expires) 
            VALUES (:id, :user_id, :ip_addr, :created_at, :expires)",
                named_params![
                    ":id": session.id(),
                    ":user_id": session.user_id(),
                    ":ip_addr": ip_str,
                    ":created_at": session.created_at(),
                    ":expires": session.expires()
                ],
            )
            .map_err(harness_error)?;
        return Ok(());
    }

    fn read_by_id(&self, id: i64) -> Result<Option<Session>, HarnessError> {
        let connection = self.connection.get().map_err(harness_error)?;
        let res = match connection.query_row(
            "SELECT * FROM sessions WHERE id = :id",
            named_params! {":id": id},
            |row| {
                // let id = row.get(0)?;
                let user_id = row.get(1)?;
                let ip_addr = row.get(2)?;
                let created_at = row.get(3)?;
                let expires = row.get(4)?;
                return Ok(Session::from_values(
                    id, user_id, ip_addr, created_at, expires,
                ));
            },
        ) {
            Ok(res) => Ok(res?),
            Err(err) => Err(err),
        };

        return map_sql_result(res);
    }

    fn read_by_user_id(&self, user_id: i64) -> Result<Option<Session>, HarnessError> {
        let connection = self.connection.get().map_err(harness_error)?;
        let res = match connection.query_row(
            "SELECT * FROM sessions WHERE user_id = :user_id",
            named_params! {":user_id": user_id},
            |row| {
                let id = row.get(0)?;
                // let user_id = row.get(1)?;
                let ip_addr = row.get(2)?;
                let created_at = row.get(3)?;
                let expires = row.get(4)?;
                return Ok(Session::from_values(
                    id, user_id, ip_addr, created_at, expires,
                ));
            },
        ) {
            Ok(res) => Ok(res?),
            Err(err) => Err(err),
        };

        return map_sql_result(res);
    }

    fn create_table(&self) -> Result<(), HarnessError> {
        let connection = self.connection.get().map_err(harness_error)?;
        connection
            .execute(CREATE_SESSION_TABLE_STATEMENT, [])
            .map_err(harness_error)?;

        return Ok(());
    }
}

const CREATE_SESSION_TABLE_STATEMENT: &'static str = "CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    ip_addr TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires DATETIME,

    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_id ON sessions(user_id);";
