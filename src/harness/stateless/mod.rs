use core::error;

use crate::{auth_token::AuthToken, session::Session};

use super::{DbHarnessSession, DbHarnessToken};

/// WARNING: Not for production use unless you have a REALLY good reason to not store sessions or tokens.
///
/// This module is particularly useful when you do not want to store a session, or tokens.
///
/// To use this method, check out [`StatelessSession] for handling your harness typedefs in side of [SessionManager](crate::core::session::SessionManager).
/// This module relies on a user to authenticate for each connection request through the [login](crate::core::user::UserManager::login) method.
pub struct StatelessSession;

impl DbHarnessSession for StatelessSession {
    fn delete(&self, _: i64) -> Result<(), Box<dyn error::Error>> {
        return Ok(());
    }
    fn insert(&self, _: &Session) -> Result<(), Box<dyn error::Error>> {
        return Ok(());
    }
    fn read_by_id(&self, _: i64) -> Result<Option<Session>, Box<dyn std::error::Error>> {
        return Ok(None);
    }
    fn read_by_user_id(&self, _: i64) -> Result<Option<Session>, Box<dyn error::Error>> {
        return Ok(None);
    }
    fn update(&self, _: &Session) -> Result<(), Box<dyn error::Error>> {
        return Ok(());
    }

    fn create_table(&self) -> Result<(), Box<dyn error::Error>> {
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
    fn create_table(&self) -> Result<(), Box<dyn std::error::Error>> {
        return Ok(());
    }
    fn delete_access_token(&self, _: i64) -> Result<(), Box<dyn std::error::Error>> {
        return Ok(());
    }

    fn delete_resfresh_token(&self, _: i64) -> Result<(), Box<dyn std::error::Error>> {
        return Ok(());
    }

    fn insert(&self, _: &crate::auth_token::AuthToken) -> Result<(), Box<dyn std::error::Error>> {
        return Ok(());
    }

    fn read_access_token(
        &self,
        _: i64,
    ) -> Result<Option<crate::auth_token::AuthToken>, Box<dyn std::error::Error>> {
        return Ok(None);
    }

    fn read_refresh_token(&self, _: i64) -> Result<Option<AuthToken>, Box<dyn std::error::Error>> {
        return Ok(None);
    }

    fn update(&self, _: &AuthToken) -> Result<(), Box<dyn std::error::Error>> {
        return Ok(());
    }
}
