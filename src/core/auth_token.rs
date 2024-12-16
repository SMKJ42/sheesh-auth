use crate::harness::DbHarnessToken;
use std::{
    error,
    fmt::{Debug, Display},
};

use super::{
    default_hash_fn, default_rng_salt_fn, default_rng_token_fn, default_verify_token_fn,
    id::{DefaultIdGenerator, IdGenerator},
};
use chrono::{offset::LocalResult, DateTime, TimeDelta, Utc};

#[derive(Debug, Clone)]
pub enum TokenType {
    Refresh { secret: String },
    Access { token: String },
}

pub enum TokenTtl {
    Refresh(i64),
    Access,
}

pub struct AuthTokenManagerConfig<T>
where
    T: IdGenerator,
{
    ttl: i64,
    id_generator: T,
    salt_fn: fn() -> String,
    token_fn: fn() -> String,
    hash_fn: fn(&str, &str) -> Result<String, AuthTokenError>,
    verify_token_fn: fn(&str, &str) -> Result<(), AuthTokenError>,
}

impl AuthTokenManagerConfig<DefaultIdGenerator> {
    pub fn default() -> Self {
        return Self {
            ttl: 30,
            id_generator: DefaultIdGenerator {},
            salt_fn: default_rng_salt_fn,
            token_fn: default_rng_token_fn,
            hash_fn: default_hash_fn,
            verify_token_fn: default_verify_token_fn,
        };
    }
}

impl<T> AuthTokenManagerConfig<T>
where
    T: IdGenerator + Copy,
{
    pub fn init<V: DbHarnessToken>(&self, harness: V) -> AuthTokenManager<T, V> {
        AuthTokenManager {
            ttl: self.ttl,
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
    ttl: i64,
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
        ttl: TokenTtl,
    ) -> Result<(AuthToken, String), TokenManagerError> {
        let id = i64::from_be_bytes(self.id_generator.new_u64().to_be_bytes());
        let token = (self.token_fn)();
        let auth_token: AuthToken;
        let secret: String;

        match ttl {
            // if we have a longer lived session token, we want to salt it.
            TokenTtl::Refresh(ttl) => {
                let salt = (self.salt_fn)();
                secret = (self.hash_fn)(&token, &salt)?;
                let token_type = TokenType::Refresh {
                    secret: secret.clone(),
                };

                auth_token = AuthToken::new(id, user_id, token_type, ttl)?;
            }

            // if we have a access token, we only want the RNG string to be stored.
            TokenTtl::Access => {
                let token_type = TokenType::Access {
                    token: token.clone(),
                };

                secret = token;
                auth_token = AuthToken::new(id, user_id, token_type, self.ttl)?;
            }
        }
        match self.harness.insert(&auth_token) {
            Ok(()) => return Ok((auth_token, secret)),
            Err(err) => return Err(TokenManagerError::Harness(err)),
        }
    }

    pub fn untrusted_verify_refresh_token(
        &self,
        token_id: i64,
        user_id: i64,
        token_str: &str,
    ) -> Result<(), TokenManagerError> {
        match self.harness.read_refresh_token(token_id) {
            Ok(token_opt) => match token_opt {
                Some(auth_token) => match self.trusted_verify_token(auth_token, user_id, token_str)
                {
                    Ok(()) => return Ok(()),
                    Err(err) => return Err(err.into()),
                },
                None => return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into()),
            },
            Err(err) => return Err(TokenManagerError::Harness(err)),
        }
    }

    pub fn untrusted_verify_access_token(
        &self,
        token_id: i64,
        user_id: i64,
        token_str: &str,
    ) -> Result<(), TokenManagerError> {
        match self.harness.read_access_token(token_id) {
            Ok(token_opt) => match token_opt {
                Some(auth_token) => match self.trusted_verify_token(auth_token, user_id, token_str)
                {
                    Ok(()) => return Ok(()),
                    Err(err) => return Err(err.into()),
                },
                None => return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into()),
            },
            Err(err) => return Err(TokenManagerError::Harness(err)),
        }
    }

    pub fn trusted_verify_token(
        &self,
        auth_token: AuthToken,
        user_id: i64,
        token_str: &str,
    ) -> Result<(), AuthTokenError> {
        if user_id != auth_token.user_id {
            return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized));
        } else if auth_token.valid == false {
            return Err(AuthTokenError::new(AuthTokenErrorKind::Invalid));
        }

        match &auth_token.token_type {
            TokenType::Access { token } => {
                if token != &token_str {
                    return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized));
                } else if auth_token.is_expired() {
                    // try to clean up, if fails, we can clean up later with a cron job.
                    let _ = self.harness.delete_access_token(auth_token.id());
                    return Err(AuthTokenError::new(AuthTokenErrorKind::Expired));
                } else {
                    return Ok(());
                }
            }
            TokenType::Refresh { secret } => {
                if auth_token.is_expired() {
                    return Err(AuthTokenError::new(AuthTokenErrorKind::Expired));
                } else {
                    return (self.verify_token_fn)(&token_str, &secret).into();
                }
            }
        }
    }

    pub fn update_token(&self, token: &AuthToken) -> Result<(), Box<dyn error::Error>> {
        self.harness.update(token)
    }

    pub fn get_access_token(&self, id: i64) -> Result<Option<AuthToken>, Box<dyn error::Error>> {
        self.harness.read_access_token(id)
    }

    // ewww....
    pub fn invalidate_token(&self, mut token: AuthToken) -> Result<(), Box<dyn error::Error>> {
        token.valid = false;
        self.harness.update(&token)?;
        return Ok(());
    }

    pub fn get_refresh_token(&self, id: i64) -> Result<Option<AuthToken>, Box<dyn error::Error>> {
        self.harness.read_refresh_token(id)
    }

    pub fn delete_access_token(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.harness.delete_access_token(id)
    }

    pub fn delete_resfresh_token(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.harness.delete_resfresh_token(id)
    }
}

#[derive(Debug)]
pub enum TokenManagerError {
    Harness(Box<dyn error::Error>),
    AuthToken(AuthTokenError),
}

impl From<AuthTokenError> for TokenManagerError {
    fn from(value: AuthTokenError) -> Self {
        return Self::AuthToken(value);
    }
}

impl Display for TokenManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl error::Error for TokenManagerError {}

#[derive(Clone, Debug)]
pub struct AuthToken {
    id: i64,
    user_id: i64,
    token_type: TokenType,
    expires: DateTime<Utc>,
    valid: bool,
}

impl AuthToken {
    /// AuthToken::new() should only be called from AuthTokenManager.
    pub fn new(
        id: i64,
        user_id: i64,
        token_type: TokenType,
        ttl: i64,
    ) -> Result<Self, AuthTokenError> {
        let expires = get_token_expiry(ttl)?;

        return Ok(AuthToken {
            id,
            user_id,
            token_type,
            expires,
            valid: true,
        });
    }

    pub fn from_values(
        id: i64,
        user_id: i64,
        token_type: TokenType,
        expires: DateTime<Utc>,
        valid: bool,
    ) -> Self {
        return Self {
            id,
            user_id,
            token_type,
            expires,
            valid,
        };
    }

    pub fn is_valid(&self) -> bool {
        return self.valid;
    }

    pub fn id(&self) -> i64 {
        return self.id;
    }

    pub fn user_id(&self) -> i64 {
        return self.user_id;
    }

    pub fn is_expired(&self) -> bool {
        return Utc::now() > self.expires;
    }

    pub fn expires(&self) -> DateTime<Utc> {
        return self.expires;
    }

    pub fn token_type(&self) -> TokenType {
        return self.token_type.clone();
    }
}

#[derive(Debug, Clone)]
pub enum AuthTokenErrorKind {
    Expired,
    Invalid,
    NotAuthorized,
    DateTime,
    Create,
    InvalidFormat,
}

impl Display for AuthTokenErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired => write!(f, "Expired"),
            Self::Invalid => write!(f, "Invalid"),
            Self::NotAuthorized => write!(f, "Not Authorized"),
            Self::DateTime => write!(f, "Error in token DateTime expiration check"),
            Self::Create => write!(f, "Could not generate token."),
            Self::InvalidFormat => write!(f, "Token stored in invalid format."),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthTokenError {
    pub kind: AuthTokenErrorKind,
}

impl AuthTokenError {
    pub fn new(kind: AuthTokenErrorKind) -> Self {
        return Self { kind };
    }
}

impl Display for AuthTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthTokenError: {}", self.kind)
    }
}

impl error::Error for AuthTokenError {}

fn get_token_expiry(ttl: i64) -> Result<DateTime<Utc>, AuthTokenError> {
    let now = Utc::now();
    let time_delta = TimeDelta::minutes(ttl);
    let (new_time, rem) = now.time().overflowing_add_signed(time_delta);
    let rem = chrono::Days::new(rem as u64);
    let now_add_day = now.checked_add_days(rem);

    match now_add_day {
        Some(some_now_add_day) => {
            let expires = some_now_add_day.with_time(new_time);
            match expires {
                LocalResult::Single(expires) => {
                    return Ok(expires);
                }
                LocalResult::Ambiguous(expires, _) => Ok(expires),
                LocalResult::None => {
                    return Err(AuthTokenError::new(AuthTokenErrorKind::DateTime));
                }
            }
        }
        None => Err(AuthTokenError::new(AuthTokenErrorKind::DateTime)),
    }
}
