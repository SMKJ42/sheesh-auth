use auth_token::{AuthTokenError, AuthTokenErrorKind};
use scrypt::password_hash::rand_core::RngCore;
use scrypt::password_hash::{
    rand_core::OsRng, Encoding, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use scrypt::{Params, Scrypt};

pub mod auth_token;
pub mod id;
pub mod session;
pub mod test;
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
