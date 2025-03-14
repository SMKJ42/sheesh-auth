use std::fmt::Display;

use chrono::{offset::LocalResult, DateTime, TimeDelta, Utc};
use scrypt::password_hash::{
    rand_core::{OsRng, RngCore},
    Encoding, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use scrypt::{Params, Scrypt};

use crate::harness::HarnessError;

// mod auth_token as priv_auth_token;
mod test;

// TODO: re-export with same namespace...
pub mod auth_token;

pub mod id;
pub mod session;
pub mod user;

// using pub static mut declaration here is doable, but would require an unsafe block.
pub fn default_rng_salt_fn() -> String {
    return SaltString::generate(OsRng).to_string();
}

// This function takes in a user provided password and a salt, then creates the hash to be stored inside of the database.
pub fn default_hash_fn<'a>(pwd: &'a str, salt: &'a str) -> Result<String, AuthTokenError> {
    let salt = SaltString::from_b64(salt)
        .map_err(|_err| AuthTokenError::new(AuthTokenErrorKind::Create))?;

    let secret = Scrypt
        .hash_password_customized(
            pwd.as_bytes(),
            None,
            None,
            Params::recommended(),
            salt.as_salt(),
        )
        .map_err(|_err| AuthTokenError::new(AuthTokenErrorKind::Create))?;

    return Ok(secret.to_string());
}

// default implementation stores the salt inside the secret, preventing required storage of the salt in a seperat field.
pub fn default_verify_token_fn(token: &str, hash: &str) -> Result<(), AuthTokenError> {
    let hash = PasswordHash::parse(hash, Encoding::B64)
        .map_err(|_err| AuthTokenError::new(AuthTokenErrorKind::InvalidFormat))?;

    return Scrypt
        .verify_password(token.as_bytes(), &hash)
        .map_err(|_err| AuthTokenError::new(AuthTokenErrorKind::NotAuthorized));
}

pub fn default_rng_token_fn() -> String {
    let left = OsRng.next_u64() as u128;
    let right = OsRng.next_u64() as u128;
    return ((left << 64) + right).to_string();
}

pub fn get_expiration(ttl: i64) -> Result<DateTime<Utc>, AuthTokenError> {
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

#[derive(Debug)]
pub enum AuthError {
    Harness(HarnessError),
    Token(AuthTokenError),
    UserNotFound,
}

// impl From<AuthError> for AuthError {
//     fn from(value: AuthError) -> Self {
//         return value;
//     }
// }

impl From<HarnessError> for AuthError {
    fn from(value: HarnessError) -> Self {
        return Self::Harness(value);
    }
}

impl From<AuthTokenError> for AuthError {
    fn from(value: AuthTokenError) -> Self {
        return Self::Token(value);
    }
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
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
