use crate::harness::{DbHarnessToken, HarnessError};
use std::fmt::Debug;

use super::{
    default_hash_fn, default_rng_salt_fn, default_rng_token_fn, default_verify_token_fn,
    get_experation,
    id::{DefaultIdGenerator, IdGenerator, ZerodIdGenerator},
    AuthError, AuthTokenError, AuthTokenErrorKind,
};
use chrono::{DateTime, Utc};

const DEFAULT_ACCESS_TTL: i64 = 30;
const DEFAULT_REFRESH_TTL: i64 = 60;

#[derive(Debug, Clone)]
pub enum TokenType {
    Refresh,
    Access,
}

pub struct TokenSecret(String);
pub struct AccessTokenSecret(String);

impl AccessTokenSecret {
    pub fn secret(&self) -> &str {
        return &self.0;
    }
}

impl From<TokenSecret> for AccessTokenSecret {
    fn from(value: TokenSecret) -> Self {
        return Self(value.0);
    }
}

pub struct RefreshTokenSecret(String);

impl RefreshTokenSecret {
    pub fn secret(&self) -> &str {
        return &self.0;
    }
}

impl From<TokenSecret> for RefreshTokenSecret {
    fn from(value: TokenSecret) -> Self {
        return Self(value.0);
    }
}

pub struct AuthTokenManagerConfig<T>
where
    T: IdGenerator,
{
    access_ttl: i64,
    refresh_ttl: i64,
    id_generator: T,
    salt_fn: fn() -> String,
    token_fn: fn() -> String,
    hash_fn: fn(&str, &str) -> Result<String, AuthTokenError>,
    verify_token_fn: fn(&str, &str) -> Result<(), AuthTokenError>,
}

impl AuthTokenManagerConfig<DefaultIdGenerator> {
    pub fn default() -> Self {
        return Self {
            access_ttl: DEFAULT_ACCESS_TTL,
            refresh_ttl: DEFAULT_REFRESH_TTL,
            id_generator: DefaultIdGenerator {},
            salt_fn: default_rng_salt_fn,
            token_fn: default_rng_token_fn,
            hash_fn: default_hash_fn,
            verify_token_fn: default_verify_token_fn,
        };
    }
}

impl AuthTokenManagerConfig<ZerodIdGenerator> {
    pub fn new_stateless() -> Self {
        return Self {
            access_ttl: DEFAULT_ACCESS_TTL,
            refresh_ttl: DEFAULT_REFRESH_TTL,
            id_generator: ZerodIdGenerator {},
            salt_fn: || return String::new(),
            token_fn: || return String::new(),
            hash_fn: |_, _| return Ok(String::new()),
            verify_token_fn: |_, _| return Ok(()),
        };
    }
}

impl<T: IdGenerator> AuthTokenManagerConfig<T> {
    pub fn new(
        id_generator: T,
        salt_fn: fn() -> String,
        token_fn: fn() -> String,
        hash_fn: fn(&str, &str) -> Result<String, AuthTokenError>,
        verify_token_fn: fn(&str, &str) -> Result<(), AuthTokenError>,
    ) -> Self {
        return Self {
            access_ttl: DEFAULT_ACCESS_TTL,
            refresh_ttl: DEFAULT_REFRESH_TTL,
            id_generator,
            salt_fn,
            token_fn,
            hash_fn,
            verify_token_fn,
        };
    }

    pub fn set_access_ttl(&mut self, new_ttl: i64) {
        self.access_ttl = new_ttl;
    }

    pub fn set_refresh_ttl(&mut self, new_ttl: i64) {
        self.refresh_ttl = new_ttl;
    }
}

impl<T> AuthTokenManagerConfig<T>
where
    T: IdGenerator + Copy,
{
    pub fn init<V: DbHarnessToken>(&self, harness: V) -> AuthTokenManager<T, V> {
        AuthTokenManager {
            access_ttl: self.access_ttl,
            refresh_ttl: self.refresh_ttl,
            id_generator: self.id_generator,
            harness,
            salt_fn: self.salt_fn,
            token_fn: self.token_fn,
            hash_fn: self.hash_fn,
            verify_token_fn: self.verify_token_fn,
        }
    }
}

pub struct AuthTokenManager<T, V>
where
    T: IdGenerator,
    V: DbHarnessToken,
{
    refresh_ttl: i64,
    access_ttl: i64,
    id_generator: T,
    salt_fn: fn() -> String,
    token_fn: fn() -> String,
    hash_fn: fn(&str, &str) -> Result<String, AuthTokenError>,
    verify_token_fn: fn(&str, &str) -> Result<(), AuthTokenError>,
    harness: V,
}

impl<T, V> AuthTokenManager<T, V>
where
    T: IdGenerator,
    V: DbHarnessToken,
{
    pub fn next_token(
        &self,
        user_id: i64,
        token_type: TokenType,
    ) -> Result<TokenSecret, AuthError> {
        let id = i64::from_be_bytes(self.id_generator.new_u64().to_be_bytes());
        let token = (self.token_fn)();
        let auth_token: AuthToken;

        let salt = (self.salt_fn)();
        let salted_hash = (self.hash_fn)(&token, &salt)?;

        match token_type {
            TokenType::Access => {
                auth_token = AuthToken::new_access(id, user_id, salted_hash, self.access_ttl)?;
            }

            TokenType::Refresh => {
                auth_token = AuthToken::new_refresh(id, user_id, salted_hash, self.refresh_ttl)?;
            }
        }

        self.harness.insert(&auth_token)?;

        return Ok(TokenSecret(token));
    }

    /// Refered to as "trusted", because the function will query the database to get token information.
    pub fn verify_refresh_token(&self, session_id: i64, token_str: &str) -> Result<(), AuthError> {
        let token_opt = self
            .harness
            .read_refresh_token(session_id)
            .map_err(|err| AuthError::Harness(err))?;

        match token_opt {
            Some(auth_token) => {
                return self
                    .verify_token(auth_token, token_str)
                    .map_err(|err| err.into());
            }
            None => return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into()),
        };
    }

    /// Refered to as "trusted", because the function will query the database to get token information.
    pub fn verify_access_token(&self, session_id: i64, token_str: &str) -> Result<(), AuthError> {
        let token_opt = self
            .harness
            .read_access_token(session_id)
            .map_err(|err| AuthError::Harness(err))?;

        match token_opt {
            Some(auth_token) => {
                return self
                    .verify_token(auth_token, token_str)
                    .map_err(|err| err.into());
            }
            None => return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into()),
        };
    }

    pub fn verify_token(
        &self,
        auth_token: AuthToken,
        token_str: &str,
    ) -> Result<(), AuthTokenError> {
        // TODO: I removed the user_id field, so I need to access this before diving into the token validation...
        //
        // if user_id != auth_token.user_id {
        // return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized));
        // } else

        if auth_token.is_expired() {
            let _ = self.harness.delete_access_token(auth_token.id());
            return Err(AuthTokenError::new(AuthTokenErrorKind::Expired));
        } else {
            return Ok((self.verify_token_fn)(&token_str, &auth_token.salted_hash)?);
        }
    }

    pub fn get_access_token(&self, id: i64) -> Result<Option<AuthToken>, HarnessError> {
        self.harness.read_access_token(id)
    }

    pub fn get_refresh_token(&self, id: i64) -> Result<Option<AuthToken>, HarnessError> {
        self.harness.read_refresh_token(id)
    }

    pub fn delete_access_token(&self, id: i64) -> Result<(), HarnessError> {
        self.harness.delete_access_token(id)
    }

    pub fn delete_access_token_by_session(&self, id: i64) -> Result<(), HarnessError> {
        self.harness.delete_access_token_by_session(id)
    }

    pub fn delete_resfresh_token(&self, id: i64) -> Result<(), HarnessError> {
        self.harness.delete_resfresh_token(id)
    }

    pub fn delete_refresh_token_by_session(&self, id: i64) -> Result<(), HarnessError> {
        self.harness.delete_refresh_token_by_session(id)
    }
}

#[derive(Clone, Debug)]
pub struct AuthToken {
    id: i64,
    session_id: i64,
    token_type: TokenType,
    salted_hash: String,
    expires: DateTime<Utc>,
}

impl AuthToken {
    pub fn new_access(
        id: i64,
        session_id: i64,
        salted_hash: String,
        ttl: i64,
    ) -> Result<Self, AuthTokenError> {
        let expires = get_experation(ttl)?;

        return Ok(AuthToken {
            id,
            session_id,
            token_type: TokenType::Access,
            salted_hash,
            expires,
        });
    }

    pub fn new_refresh(
        id: i64,
        session_id: i64,
        salted_hash: String,
        ttl: i64,
    ) -> Result<Self, AuthTokenError> {
        let expires = get_experation(ttl)?;

        return Ok(AuthToken {
            id,
            session_id,
            token_type: TokenType::Refresh,
            salted_hash,
            expires,
        });
    }

    pub fn from_values(
        id: i64,
        session_id: i64,
        salted_hash: String,
        token_type: TokenType,
        expires: DateTime<Utc>,
    ) -> Self {
        return Self {
            id,
            session_id,
            salted_hash,
            token_type,
            expires,
        };
    }

    pub fn id(&self) -> i64 {
        return self.id;
    }

    pub fn session_id(&self) -> i64 {
        return self.session_id;
    }

    pub fn is_expired(&self) -> bool {
        return Utc::now() > self.expires;
    }

    pub fn expires(&self) -> DateTime<Utc> {
        return self.expires;
    }

    pub fn salted_hash(&self) -> &str {
        return &self.salted_hash;
    }

    pub fn token_type(&self) -> TokenType {
        return self.token_type.clone();
    }
}
