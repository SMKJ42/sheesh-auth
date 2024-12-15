mod entity;

pub mod session;
pub mod token;
pub mod user;

use session::*;
use token::*;
use user::*;

use rusqlite::ToSql;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use super::DbHarness;

impl<'a> DbHarness<SqliteHarnessUser<'a>, SqliteHarnessSession, SqliteHarnessToken> {
    pub fn new_sqlite(pool: Pool<SqliteConnectionManager>) -> Self {
        return DbHarness {
            user: SqliteHarnessUser::new(pool.clone()),
            session: SqliteHarnessSession::new(pool.clone()),
            token: SqliteHarnessToken::new(pool),
        };
    }
}

pub trait IntoValues {
    fn into_values(&self) -> &[(&str, &dyn ToSql)];
}
