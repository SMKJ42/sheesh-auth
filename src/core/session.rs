use std::error;

use crate::harness::{DbHarnessSession, DbHarnessToken};

use super::{
    auth_token::{
        AuthToken, AuthTokenError, AuthTokenErrorKind, AuthTokenManager, AuthTokenManagerConfig,
        TokenManagerError, TokenTtl,
    },
    id::{DefaultIdGenerator, IdGenerator},
};

// Session naming convention may be a bit misleading. it is really to handle the refresh token on the auth server iteself...
// the client server will also have a session entity representing the user's session within the application
pub struct SessionManagerConfig<T>
where
    T: IdGenerator,
{
    id_generator: T,
    token_manager_config: AuthTokenManagerConfig<T>,
    ttl: i64,
}

impl Default for SessionManagerConfig<DefaultIdGenerator> {
    fn default() -> Self {
        return Self {
            id_generator: DefaultIdGenerator {},
            token_manager_config: AuthTokenManagerConfig::default(),
            ttl: 240,
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
            id_generator: self.id_generator,
            harness: session_harness,
            ttl: self.ttl,
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
    id_generator: T,
    token_manager: AuthTokenManager<T, X>,
    harness: V,
    ttl: i64,
}

pub struct RefreshSecret(String);

impl RefreshSecret {
    pub fn as_str(&self) -> &str {
        return &self.0;
    }
}
pub struct AccessSecret(String);

impl AccessSecret {
    pub fn as_str(&self) -> &str {
        return &self.0;
    }
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
    ) -> Result<(Session, RefreshSecret, AccessSecret), Box<dyn error::Error>> {
        let id = self.id_generator.new_u64();

        let (refresh_token, refresh_secret) = self
            .token_manager
            .next_token(user_id, TokenTtl::Refresh(self.ttl))?;

        let (access_token, access_secret) =
            self.token_manager.next_token(user_id, TokenTtl::Access)?;

        let session = Session {
            // shift to bytes then into i64 (DO NOT CAST, we want to preserve the bit values)
            id: i64::from_be_bytes(id.to_be_bytes()),
            user_id,
            refresh_token: Some(refresh_token.id()),
            access_token: Some(access_token.id()),
        };
        self.harness.insert(&session)?;

        return Ok((
            session,
            RefreshSecret(refresh_secret),
            AccessSecret(access_secret),
        ));
    }

    pub fn verify_session_token(
        &self,
        token_id: i64,
        user_id: i64,
        user_token_atmpt: &str,
    ) -> Result<(), TokenManagerError> {
        self.token_manager
            .untrusted_verify_refresh_token(token_id, user_id, user_token_atmpt)
    }

    pub fn verify_access_token(
        &self,
        token_id: i64,
        user_id: i64,
        user_token_atmpt: &str,
    ) -> Result<(), TokenManagerError> {
        self.token_manager
            .untrusted_verify_access_token(token_id, user_id, user_token_atmpt)
    }

    pub fn trusted_verify_token(
        &self,
        token: AuthToken,
        user_id: i64,
        user_token_atmpt: &str,
    ) -> Result<(), AuthTokenError> {
        self.token_manager
            .trusted_verify_token(token, user_id, user_token_atmpt)
    }

    pub fn get_session(&self, id: i64) -> Result<Session, Box<dyn error::Error>> {
        return self.harness.read(id);
    }

    pub fn create_new_access_token(
        &self,
        session: &mut Session,
        user_id: i64,
    ) -> Result<AccessSecret, Box<dyn error::Error>> {
        // cleanup old token
        match session.access_token {
            Some(token_id) => {
                // cleanup old access token
                self.token_manager.delete_access_token(token_id)?;
            }
            // no access token to cleanup, we can continue...
            None => {}
        }

        let (new_token, access_token_secret) =
            self.token_manager.next_token(user_id, TokenTtl::Access)?;

        session.access_token = Some(new_token.id());

        //update the session with the new token id.
        self.harness.update(session)?;

        return Ok(AccessSecret(access_token_secret));
    }

    /// while session does have a user_id field, we do not want to verify the user id from this struct,
    /// instead the user id should be supplied from the user request.
    pub fn create_new_refresh_token(
        &self,
        session: &mut Session,
        user_id: i64,
        user_token_atmpt: &RefreshSecret,
    ) -> Result<(RefreshSecret, AccessSecret), TokenManagerError> {
        let refresh_token: Option<AuthToken>;

        // retrieve the persisted token from db
        match session.refresh_token {
            Some(token_id) => {
                let refresh_token_res = self.token_manager.get_refresh_token(token_id);
                // check for harness error.
                match refresh_token_res {
                    // check to ensure we obtained a token.
                    Ok(token) => refresh_token = token,

                    // the harness failed to fetch the provided refresh token, return an error...
                    Err(err) => return Err(TokenManagerError::Harness(err)),
                }
            }
            None => {
                // if the session has a None value in the session token, there is no 'old' refresh token to check.
                return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into());
            }
        }

        // Check if the token exists
        match &refresh_token {
            // if we obtained a token, validate it.
            Some(token) => {
                match self.token_manager.trusted_verify_token(
                    token.clone(),
                    user_id,
                    user_token_atmpt.as_str(),
                ) {
                    Ok(_) => {
                        // The provided token is valid, we can continue...
                    }

                    Err(err) => {
                        match err.kind {
                            AuthTokenErrorKind::Expired | AuthTokenErrorKind::Invalid => {
                                // if we hit this area, someone has accessed an expired or invalidated refresh token.
                                // When this happens, we want to invalidate the session and return an error.
                                self.set_token_ids_none(session)?;
                                // Change the error to reflect the new state of the session.
                                return Err(
                                    AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into()
                                );
                            }
                            _ => {
                                // propogate the wildcard error
                                return Err(err.into());
                            }
                        }
                    }
                }
            }

            // No token found in the database, return an error...
            None => {
                return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into());
            }
        }

        // create the new refresh token...
        let (refresh_token, refresh_token_secret) = self
            .token_manager
            .next_token(user_id, TokenTtl::Refresh(self.ttl))?;

        // create a new access token...
        // creating it this way instead of the already build harness allows
        let (access_token, access_token_secret) =
            self.token_manager.next_token(user_id, TokenTtl::Access)?;

        // save the tokens to the session
        session.refresh_token = Some(refresh_token.id());
        session.access_token = Some(access_token.id());

        match self.harness.update(&session) {
            Ok(()) => {
                return Ok((
                    RefreshSecret(refresh_token_secret),
                    AccessSecret(access_token_secret),
                ))
            }
            Err(err) => return Err(TokenManagerError::Harness(err)),
        }
    }

    pub fn set_token_ids_none(&self, session: &mut Session) -> Result<(), TokenManagerError> {
        session.access_token = None;
        session.refresh_token = None;

        match self.harness.update(&session) {
            Err(err) => return Err(TokenManagerError::Harness(err)),
            Ok(()) => Ok(()),
        }
    }

    pub fn invalidate_session(&self, mut session: Session) -> Result<(), TokenManagerError> {
        match session.refresh_token {
            Some(token_id) => {
                let _ = self.token_manager.delete_resfresh_token(token_id);
                session.refresh_token = None;
            }
            None => {}
        }
        match session.access_token {
            Some(token_id) => {
                let _ = self.token_manager.delete_access_token(token_id);
                session.access_token = None;
            }
            None => {}
        }
        match self.harness.update(&session) {
            Err(err) => return Err(TokenManagerError::Harness(err)),
            Ok(()) => Ok(()),
        }
    }

    pub fn invalidate_access_token(&self, session: &mut Session) -> Result<(), TokenManagerError> {
        match session.access_token {
            Some(token_id) => match self.token_manager.delete_access_token(token_id) {
                Ok(()) => {
                    session.access_token = None;
                    return Ok(());
                }
                Err(err) => return Err(TokenManagerError::Harness(err)),
            },
            None => todo!(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Session {
    id: i64,
    user_id: i64,
    refresh_token: Option<i64>,
    access_token: Option<i64>,
}

impl Session {
    pub fn from_values(
        id: i64,
        user_id: i64,
        refresh_token: Option<i64>,
        access_token: Option<i64>,
    ) -> Self {
        return Self {
            id,
            user_id,
            refresh_token,
            access_token,
        };
    }

    pub fn id(&self) -> i64 {
        return self.id;
    }

    pub fn user_id(&self) -> i64 {
        return self.user_id;
    }

    pub fn refresh_token(&self) -> Option<i64> {
        return self.refresh_token;
    }

    pub fn access_token(&self) -> Option<i64> {
        return self.access_token;
    }
}
