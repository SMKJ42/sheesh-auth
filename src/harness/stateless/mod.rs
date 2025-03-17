use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{
    auth_token::AuthToken,
    id::ZerodIdGenerator,
    session::{Session, SessionManager, SessionManagerConfig},
    user::UserManagerConfig,
};

use super::{sqlite::SqliteUserManager, DbHarness, DbHarnessSession, DbHarnessToken, HarnessError};

/// WARNING: Not for production use unless you have a REALLY good reason to not store sessions or tokens.
///
/// This module is particularly useful when you do not want to store a session, or tokens.
///
/// To use this method, check out [`StatelessSession] for handling your harness typedefs in side of [SessionManager](crate::core::session::SessionManager).
/// This module relies on a user to authenticate for each connection request through the [login](crate::core::user::UserManager::login) method.
pub struct StatelessSession;

impl DbHarnessSession for StatelessSession {
    fn delete(&self, _id: i64) -> Result<(), HarnessError> {
        return Ok(());
    }
    fn insert(&self, _session: &Session) -> Result<(), HarnessError> {
        return Ok(());
    }
    fn read_by_id(&self, _id: i64) -> Result<Option<Session>, HarnessError> {
        return Ok(None);
    }
    fn create_table(&self) -> Result<(), HarnessError> {
        return Ok(());
    }
    fn read_by_user_id(&self, _user_id: i64) -> Result<Option<Session>, HarnessError> {
        return Ok(None);
    }
}

/// WARNING: Not for production use unless you have a REALLY good reason to not store sessions or tokens.
///
/// This module is particularly useful when you do not want to store a session, or tokens.
///
/// To use this method, check out [`StatelessSession`] for handling your harness typedefs in side of [SessionManager](crate::core::session::SessionManager).
/// This module relies on a user to authenticate for each connection request through the [login](crate::core::user::UserManager::login) method.
pub struct StatelessToken;

impl DbHarnessToken for StatelessToken {
    fn create_table(&self) -> Result<(), HarnessError> {
        return Ok(());
    }
    fn delete_access_token(&self, _: i64) -> Result<(), HarnessError> {
        return Ok(());
    }

    fn delete_resfresh_token(&self, _: i64) -> Result<(), HarnessError> {
        return Ok(());
    }

    fn delete_access_token_by_session(&self, _: i64) -> Result<(), HarnessError> {
        return Ok(());
    }

    fn delete_refresh_token_by_session(&self, _: i64) -> Result<(), HarnessError> {
        return Ok(());
    }

    fn insert(&self, _: &crate::auth_token::AuthToken) -> Result<(), HarnessError> {
        return Ok(());
    }

    fn read_access_token(
        &self,
        _: i64,
    ) -> Result<Option<crate::auth_token::AuthToken>, HarnessError> {
        return Ok(None);
    }

    fn read_refresh_token(&self, _: i64) -> Result<Option<AuthToken>, HarnessError> {
        return Ok(None);
    }
}

pub type StatelessSessionManager =
    SessionManager<ZerodIdGenerator, StatelessSession, StatelessToken>;

pub fn init_stateless_sqlite_config(
    pool: Pool<SqliteConnectionManager>,
) -> Result<(SqliteUserManager, StatelessSessionManager), HarnessError> {
    let harness = DbHarness::new_stateless_sqlite(pool).init()?;
    let user_manager = UserManagerConfig::default().init(harness.user);
    let session_manager =
        SessionManagerConfig::new_stateless().init(harness.session, harness.token);

    return Ok((user_manager, session_manager));
}
