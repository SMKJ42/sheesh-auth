use std::error;

use crate::harness::{DbHarnessSession, DbHarnessToken};

use super::{
    auth_token::{
        AuthToken, AuthTokenError, AuthTokenErrorKind, AuthTokenManager, AuthTokenManagerConfig,
        TokenManagerError, TokenType,
    },
    id::{DefaultIdGenerator, IdGenerator, ZerodIdGenerator},
};

// Session naming convention may be a bit misleading. it is really to handle the refresh token on the auth server iteself...
// the client server will also have a session entity representing the user's session within the application
pub struct SessionManagerConfig<T>
where
    T: IdGenerator,
{
    id_generator: T,
    token_manager_config: AuthTokenManagerConfig<T>,
}

impl Default for SessionManagerConfig<DefaultIdGenerator> {
    fn default() -> Self {
        return Self {
            id_generator: DefaultIdGenerator {},
            token_manager_config: AuthTokenManagerConfig::default(),
        };
    }
}

impl SessionManagerConfig<ZerodIdGenerator> {
    pub fn new_stateless() -> Self {
        return Self {
            id_generator: ZerodIdGenerator {},
            token_manager_config: AuthTokenManagerConfig::new_stateless(),
        };
    }
}

impl<T: IdGenerator> SessionManagerConfig<T> {
    pub fn new(id_generator: T, token_config: AuthTokenManagerConfig<T>) -> Self {
        return Self {
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
    id_generator: T,
    token_manager: AuthTokenManager<T, X>,
    harness: V,
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

        let (refresh_token, refresh_secret) =
            self.token_manager.next_token(user_id, TokenType::Refresh)?;

        let (access_token, access_secret) =
            self.token_manager.next_token(user_id, TokenType::Access)?;

        let session = Session::new(
            i64::from_be_bytes(id.to_be_bytes()),
            user_id,
            Some(refresh_token.id()),
            Some(access_token.id()),
        );

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

    pub fn get_users_session(&self, id: i64) -> Result<Option<Session>, Box<dyn error::Error>> {
        return self.harness.read_by_user_id(id);
    }

    pub fn get_session_by_id(&self, id: i64) -> Result<Option<Session>, Box<dyn error::Error>> {
        return self.harness.read_by_id(id);
    }

    pub fn create_new_access_token(
        &self,
        session: &mut Session,
        user_id: i64,
    ) -> Result<AccessSecret, Box<dyn error::Error>> {
        // cleanup old token
        match session.access_token() {
            Some(token_id) => {
                // cleanup old access token
                self.token_manager.delete_access_token(token_id)?;
            }
            // no access token to cleanup, we can continue...
            None => {}
        }

        let (new_token, access_token_secret) =
            self.token_manager.next_token(user_id, TokenType::Access)?;

        session.set_access_token(Some(new_token.id()));

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
        match session.refresh_token() {
            Some(token_id) => {
                refresh_token = self
                    .token_manager
                    .get_refresh_token(token_id)
                    .map_err(|err| TokenManagerError::Harness(err))?;
            }
            None => {
                // if the session has a None value in the session token, there is no 'old' refresh token to check.
                return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into());
            }
        }

        // Check if the token exists
        match &refresh_token {
            // if we obtained a token, validate it.
            Some(token) => self.token_manager.trusted_verify_token(
                token.clone(),
                user_id,
                user_token_atmpt.as_str(),
            )?,

            // No token found in the database, return an error...
            None => {
                return Err(AuthTokenError::new(AuthTokenErrorKind::NotAuthorized).into());
            }
        }

        // create the new refresh token...
        let (refresh_token, refresh_token_secret) =
            self.token_manager.next_token(user_id, TokenType::Refresh)?;

        // create a new access token...
        // creating it this way instead of the already build harness allows
        let (access_token, access_token_secret) =
            self.token_manager.next_token(user_id, TokenType::Access)?;

        // save the tokens to the session
        session.set_access_token(Some(refresh_token.id()));
        session.set_access_token(Some(access_token.id()));

        self.harness
            .update(&session)
            .map_err(|err| TokenManagerError::Harness(err))?;

        return Ok((
            RefreshSecret(refresh_token_secret),
            AccessSecret(access_token_secret),
        ));
    }

    pub fn invalidate_session(&self, mut session: Session) -> Result<(), TokenManagerError> {
        match session.refresh_token() {
            Some(token_id) => {
                let _ = self.token_manager.delete_resfresh_token(token_id);
                session.set_refresh_token(None);
            }
            None => {}
        }
        match session.access_token() {
            Some(token_id) => {
                let _ = self.token_manager.delete_access_token(token_id);
                session.set_access_token(None);
            }
            None => {}
        }

        return self
            .harness
            .update(&session)
            .map_err(|err| TokenManagerError::Harness(err));
    }

    pub fn invalidate_access_token(&self, session: &mut Session) -> Result<(), TokenManagerError> {
        match session.access_token() {
            Some(token_id) => {
                self.token_manager
                    .delete_access_token(token_id)
                    .map_err(|err| TokenManagerError::Harness(err))?;
                session.set_access_token(None);
                return Ok(());
            }
            None => todo!(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Session {
    id: i64,
    user_id: i64,
    refresh_token_id: Option<i64>,
    access_token_id: Option<i64>,
}

impl Session {
    pub fn new(
        id: i64,
        user_id: i64,
        refresh_token_id: Option<i64>,
        access_token_id: Option<i64>,
    ) -> Self {
        return Self {
            id,
            user_id,
            refresh_token_id,
            access_token_id,
        };
    }

    /// Obtain a session from no values. This is usually not the inteded behavior, but is instead used for authentication methods where tokens are not issued,
    /// but instead authentication is performed on a per connection basis.
    pub fn stateless() -> Self {
        return Self {
            id: 0,
            user_id: 0,
            refresh_token_id: None,
            access_token_id: None,
        };
    }

    pub fn from_values(
        id: i64,
        user_id: i64,
        refresh_token_id: Option<i64>,
        access_token_id: Option<i64>,
    ) -> Self {
        return Self {
            id,
            user_id,
            refresh_token_id,
            access_token_id,
        };
    }

    pub fn id(&self) -> i64 {
        return self.id;
    }

    pub fn user_id(&self) -> i64 {
        return self.user_id;
    }

    pub fn refresh_token(&self) -> Option<i64> {
        return self.refresh_token_id;
    }

    fn set_refresh_token(&mut self, refresh_token_id: Option<i64>) {
        self.refresh_token_id = refresh_token_id
    }

    pub fn access_token(&self) -> Option<i64> {
        return self.access_token_id;
    }

    fn set_access_token(&mut self, access_token_id: Option<i64>) {
        self.access_token_id = access_token_id;
    }
}
