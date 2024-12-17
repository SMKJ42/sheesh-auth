use core::error;

use crate::{auth_token::AuthToken, session::Session};

use super::{DbHarnessSession, DbHarnessToken};

pub struct StatelessSession;

impl DbHarnessSession for StatelessSession {
    fn delete(&self, _: i64) -> Result<(), Box<dyn error::Error>> {
        return Ok(());
    }
    fn insert(&self, _: &Session) -> Result<(), Box<dyn error::Error>> {
        return Ok(());
    }
    fn read(&self, _: i64) -> Result<Session, Box<dyn error::Error>> {
        return Ok(Session::stateless());
    }
    fn update(&self, _: &Session) -> Result<(), Box<dyn error::Error>> {
        return Ok(());
    }

    fn create_table(&self) -> Result<(), Box<dyn error::Error>> {
        return Ok(());
    }
}

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
