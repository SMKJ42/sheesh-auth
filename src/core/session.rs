use std::{net::IpAddr, str::FromStr};

use chrono::{DateTime, Utc};

use crate::harness::{harness_error, DbHarnessSession, DbHarnessToken, HarnessError};

use super::{
    auth_token::{AccessToken, AuthTokenManager, AuthTokenManagerConfig, RefreshToken, TokenType},
    get_expiration,
    id::{DefaultIdGenerator, IdGenerator, ZerodIdGenerator},
    AuthError, AuthTokenError,
};

pub struct SessionManagerConfig<T>
where
    T: IdGenerator,
{
    session_ttl: Option<i64>,
    id_generator: T,
    token_manager_config: AuthTokenManagerConfig<T>,
}

impl Default for SessionManagerConfig<DefaultIdGenerator> {
    fn default() -> Self {
        return Self {
            session_ttl: None,
            id_generator: DefaultIdGenerator {},
            token_manager_config: AuthTokenManagerConfig::default(),
        };
    }
}

impl SessionManagerConfig<ZerodIdGenerator> {
    pub fn new_stateless() -> Self {
        return Self {
            session_ttl: None,
            id_generator: ZerodIdGenerator {},
            token_manager_config: AuthTokenManagerConfig::new_stateless(),
        };
    }
}

impl<T: IdGenerator> SessionManagerConfig<T> {
    pub fn new(
        session_ttl: Option<i64>,
        id_generator: T,
        token_config: AuthTokenManagerConfig<T>,
    ) -> Self {
        return Self {
            session_ttl,
            id_generator,
            token_manager_config: token_config,
        };
    }
}

impl<T> SessionManagerConfig<T>
where
    T: IdGenerator + Copy,
{
    pub fn init<V: DbHarnessSession, Y: DbHarnessToken>(
        &self,
        session_harness: V,
        token_harness: Y,
    ) -> SessionManager<T, V, Y> {
        return SessionManager {
            session_ttl: self.session_ttl,
            id_generator: self.id_generator,
            harness: session_harness,
            token_manager: self.token_manager_config.init(token_harness),
        };
    }
}

pub struct SessionManager<T, V, X>
where
    T: IdGenerator,
    V: DbHarnessSession,
    X: DbHarnessToken,
{
    session_ttl: Option<i64>,
    id_generator: T,
    token_manager: AuthTokenManager<T, X>,
    harness: V,
}

impl<T, V, X> SessionManager<T, V, X>
where
    T: IdGenerator,
    V: DbHarnessSession,
    X: DbHarnessToken,
{
    pub fn new_session(
        &self,
        user_id: i64,
        ip_addr: Option<IpAddr>,
    ) -> Result<(Session, RefreshToken, AccessToken), AuthError> {
        let id = self.id_generator.new_u64();

        let session = Session::new(
            i64::from_be_bytes(id.to_be_bytes()),
            user_id,
            ip_addr,
            self.session_ttl,
        )?;

        self.harness.insert(&session)?;

        let refresh_secret = self
            .token_manager
            .next_token(session.id(), TokenType::Refresh)?;

        let access_secret = self
            .token_manager
            .next_token(session.id(), TokenType::Access)?;

        return Ok((session, refresh_secret.into(), access_secret.into()));
    }

    pub fn verify_refresh_token(
        &self,
        session_id: i64,
        user_token_atmpt: &RefreshToken,
    ) -> Result<Session, AuthError> {
        if let Some(session) = self.harness.read_by_id(session_id).unwrap() {
            self.token_manager
                .verify_refresh_token(session_id, user_token_atmpt.0.secret())?;
            return Ok(session);
        } else {
            return Err(AuthError::Token(AuthTokenError::new(
                super::AuthTokenErrorKind::NotAuthorized,
            )));
        }
    }

    pub fn verify_access_token(
        &self,
        session_id: i64,
        user_token_atmpt: &AccessToken,
    ) -> Result<Session, AuthError> {
        if let Some(session) = self.harness.read_by_id(session_id).unwrap() {
            self.token_manager
                .verify_access_token(session_id, user_token_atmpt.0.secret())?;
            return Ok(session);
        } else {
            return Err(AuthError::Token(AuthTokenError::new(
                super::AuthTokenErrorKind::NotAuthorized,
            )));
        }
    }

    pub fn get_session_by_id(&self, id: i64) -> Result<Option<Session>, HarnessError> {
        return self.harness.read_by_id(id);
    }

    pub fn create_new_access_token(&self, session: &Session) -> Result<AccessToken, AuthError> {
        self.token_manager
            .delete_access_token_by_session(session.id())?;

        let access_token_secret = self
            .token_manager
            .next_token(session.id(), TokenType::Access)?;

        return Ok(access_token_secret.into());
    }

    /// Deletes the old access and refresh token and then returns new tokens.
    pub fn create_new_refresh_token(
        &self,
        session: &Session,
    ) -> Result<(RefreshToken, AccessToken), AuthError> {
        self.token_manager
            .delete_refresh_token_by_session(session.id())?;

        // cleanup old token
        self.token_manager
            .delete_access_token_by_session(session.id())
            .map_err(|err| AuthError::Harness(err))?;

        let access_token_secret = self
            .token_manager
            .next_token(session.id(), TokenType::Access)?;
        let refresh_token_secret = self
            .token_manager
            .next_token(session.id(), TokenType::Refresh)?;

        return Ok((refresh_token_secret.into(), access_token_secret.into()));
    }

    /// Deletes the associated tokens inside the database, but leaves the session itself intact.
    pub fn delete_session(&self, session_id: i64) -> Result<(), AuthError> {
        self.token_manager
            .delete_access_token_by_session(session_id)
            .map_err(|err| AuthError::Harness(err))?;

        return self
            .token_manager
            .delete_refresh_token_by_session(session_id)
            .map_err(|err| AuthError::Harness(err));
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Session {
    id: i64,
    user_id: i64,
    ip_addr: Option<IpAddr>,
    created_at: DateTime<Utc>,
    expires: DateTime<Utc>,
}

const MAX_UTC: DateTime<Utc> = DateTime::<Utc>::MAX_UTC;

impl Session {
    pub fn new(
        id: i64,
        user_id: i64,
        ip_adrr: Option<IpAddr>,
        ttl: Option<i64>,
    ) -> Result<Self, AuthTokenError> {
        let expires = if let Some(ttl) = ttl {
            get_expiration(ttl)?
        } else {
            MAX_UTC
        };

        return Ok(Self {
            id,
            user_id,
            ip_addr: ip_adrr,
            created_at: Utc::now(),
            expires,
        });
    }

    /// Obtain a session from no values. This is usually not the inteded behavior, but is instead used for authentication methods where tokens are not issued,
    /// but instead authentication is performed on a per connection basis.
    pub fn stateless() -> Self {
        return Self {
            id: 0,
            user_id: 0,
            ip_addr: None,
            created_at: Utc::now(),
            expires: MAX_UTC,
        };
    }

    pub fn from_values(
        id: i64,
        user_id: i64,
        ip_addr: Option<String>,
        created_at: DateTime<Utc>,
        expires: DateTime<Utc>,
    ) -> Result<Self, HarnessError> {
        let ip_addr = if let Some(ip_str) = ip_addr {
            Some(IpAddr::from_str(&ip_str).map_err(harness_error)?)
        } else {
            None
        };

        return Ok(Self {
            id,
            user_id,
            ip_addr,
            created_at,
            expires,
        });
    }

    pub fn id(&self) -> i64 {
        return self.id;
    }

    pub fn user_id(&self) -> i64 {
        return self.user_id;
    }

    pub fn ip_addr(&self) -> Option<IpAddr> {
        return self.ip_addr;
    }

    pub fn expires(&self) -> DateTime<Utc> {
        return self.expires;
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        return self.created_at;
    }
}
