mod entity;

pub mod session;
mod test;
pub mod token;
pub mod user;

use crate::{
    id::DefaultIdGenerator,
    session::{SessionManager, SessionManagerConfig},
    user::{UserManager, UserManagerConfig},
};

use self::{session::SqliteHarnessSession, token::SqliteHarnessToken, user::SqliteHarnessUser};

use rusqlite::ToSql;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use super::{
    stateless::{StatelessSession, StatelessToken},
    DbHarness, HarnessError,
};

/// A default table schema for users, sessions and tokens.
impl DbHarness<SqliteHarnessUser, SqliteHarnessSession, SqliteHarnessToken> {
    pub fn new_sqlite(pool: Pool<SqliteConnectionManager>) -> Self {
        return DbHarness {
            user: SqliteHarnessUser::new(pool.clone()),
            session: SqliteHarnessSession::new(pool.clone()),
            token: SqliteHarnessToken::new(pool),
        };
    }
}

/// WARNING: Not for production use unless you have a REALLY good reason to not store sessions or tokens.
///
/// This module is particularly useful when you do not want to store a session, or tokens.
///
/// This module relies on a user to authenticate for each connection request through the [login](crate::core::user::UserManager::login) method.
impl DbHarness<SqliteHarnessUser, StatelessSession, StatelessToken> {
    pub fn new_stateless_sqlite(pool: Pool<SqliteConnectionManager>) -> Self {
        return DbHarness {
            user: SqliteHarnessUser::new(pool),
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

pub type SqliteUserManager = UserManager<DefaultIdGenerator, SqliteHarnessUser>;
pub type SqliteSessionManager =
    SessionManager<DefaultIdGenerator, SqliteHarnessSession, SqliteHarnessToken>;

/// Call this function to obtain a user and session manager. This function also creates the 'users', 'sessions', 'auth_tokens' and 'refres_tokens' tables
/// # Errors:
/// On failure to create the sqlite tables.
pub fn init_tables_sqlite_config(
    pool: Pool<SqliteConnectionManager>,
) -> Result<(SqliteUserManager, SqliteSessionManager), HarnessError> {
    let harness = DbHarness::new_sqlite(pool).init()?;
    let user_manager = UserManagerConfig::default().init(harness.user);
    let session_manager = SessionManagerConfig::default().init(harness.session, harness.token);
    return Ok((user_manager, session_manager));
}

/// Call this function to obtain a user and session manager. It has no side effects.
pub fn init_sqlite_config(
    pool: Pool<SqliteConnectionManager>,
) -> Result<(SqliteUserManager, SqliteSessionManager), HarnessError> {
    let harness = DbHarness::new_sqlite(pool);
    let user_manager = UserManagerConfig::default().init(harness.user);
    let session_manager = SessionManagerConfig::default().init(harness.session, harness.token);
    return Ok((user_manager, session_manager));
}
