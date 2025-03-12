mod entity;

pub mod session;
mod test;
pub mod token;
pub mod user;

use self::{session::SqliteHarnessSession, token::SqliteHarnessToken, user::SqliteHarnessUser};

use rusqlite::ToSql;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use super::{
    stateless::{StatelessSession, StatelessToken},
    DbHarness, HarnessError,
};

/// A default table schema for users, sessions and tokens.
impl<'a> DbHarness<SqliteHarnessUser<'a>, SqliteHarnessSession<'a>, SqliteHarnessToken<'a>> {
    pub fn new_sqlite(pool: &'a Pool<SqliteConnectionManager>) -> Self {
        return DbHarness {
            user: SqliteHarnessUser::new(&pool),
            session: SqliteHarnessSession::new(&pool),
            token: SqliteHarnessToken::new(&pool),
        };
    }
}

/// WARNING: Not for production use unless you have a REALLY good reason to not store sessions or tokens.
///
/// This module is particularly useful when you do not want to store a session, or tokens.
///
/// This module relies on a user to authenticate for each connection request through the [login](crate::core::user::UserManager::login) method.
impl<'a> DbHarness<SqliteHarnessUser<'a>, StatelessSession, StatelessToken> {
    pub fn new_stateless_sqlite(pool: &'a Pool<SqliteConnectionManager>) -> Self {
        return DbHarness {
            user: SqliteHarnessUser::new(&pool),
            session: StatelessSession,
            token: StatelessToken,
        };
    }
}

pub trait IntoValues {
    fn into_values(&self) -> &[(&str, &dyn ToSql)];
}

pub fn map_sql_result<T>(res: Result<T, rusqlite::Error>) -> Result<Option<T>, HarnessError> {
    return match res {
        Ok(session) => Ok(Some(session)),
        Err(err) => match err {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            _ => Err(HarnessError(Box::new(err))),
        },
    };
}
