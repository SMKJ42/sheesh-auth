use crate::{auth_token::AuthToken, session::Session};

use super::{DbHarnessSession, DbHarnessToken, HarnessError};

/// WARNING: Not for production use unless you have a REALLY good reason to not store sessions or tokens.
///
/// This module is particularly useful when you do not want to store a session, or tokens.
///
/// To use this method, check out [`StatelessSession] for handling your harness typedefs in side of [SessionManager](crate::core::session::SessionManager).
/// This module relies on a user to authenticate for each connection request through the [login](crate::core::user::UserManager::login) method.
pub struct StatelessSession;

impl DbHarnessSession for StatelessSession {
    fn delete(&self, _: i64) -> Result<(), HarnessError> {
        return Ok(());
    }
    fn insert(&self, _: &Session) -> Result<(), HarnessError> {
        return Ok(());
    }
    fn read_by_id(&self, _: i64) -> Result<Option<Session>, HarnessError> {
        return Ok(None);
    }
    fn read_by_user_id(&self, _: i64) -> Result<Option<Session>, HarnessError> {
        return Ok(None);
    }
    fn create_table(&self) -> Result<(), HarnessError> {
        return Ok(());
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

    // fn invalidate(&self, _: &AuthToken) -> Result<(), HarnessError> {
    //     return Ok(());
    // }
}
