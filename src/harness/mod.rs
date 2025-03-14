pub mod mysql;
pub mod postgresql;
pub mod sqlite;
pub mod stateless;

use std::{error, fmt::Display};

use stateless::{StatelessSession, StatelessToken};

use crate::{auth_token::AuthToken, session::Session, user::UserData};

pub enum Db {
    MySql,
    Postgresql,
    Sqlite,
}

#[derive(Debug)]
pub struct HarnessError(Box<dyn error::Error>);

pub fn harness_error(err: impl error::Error + 'static) -> HarnessError {
    return HarnessError::new(Box::new(err));
}

impl HarnessError {
    pub fn new(err: Box<dyn error::Error>) -> Self {
        return Self(err);
    }
}

impl error::Error for HarnessError {}

impl Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "Harness Error: {}", self.0);
    }
}

impl From<Box<dyn error::Error>> for HarnessError {
    fn from(value: Box<dyn error::Error>) -> Self {
        return Self(value);
    }
}

pub trait DbHarnessUser {
    fn create_table(&self) -> Result<(), HarnessError>;
    fn read_by_id(&self, id: i64) -> Result<Option<UserData>, HarnessError>;
    fn read_by_username(&self, username: &str) -> Result<Option<UserData>, HarnessError>;
    fn update(&self, item: &UserData) -> Result<(), HarnessError>;

    fn insert(&self, item: &UserData) -> Result<(), HarnessError>;
    fn delete(&self, id: i64) -> Result<(), HarnessError>;

    // A function to update the salted_hash, calling .update() will not update this field.
    fn update_salted_hash(&self, id: i64, salted_hash: &str) -> Result<(), HarnessError>;
}

pub trait DbHarnessUserExt: DbHarnessUser {
    fn update_username(&self, id: i64, username: &str) -> Result<(), HarnessError>;
    fn set_ban(&self, id: i64, ban: bool) -> Result<(), HarnessError>;
    fn set_attempts(&self, id: i64, count: i64) -> Result<(), HarnessError>;
}

pub trait DbHarnessSession {
    fn create_table(&self) -> Result<(), HarnessError>;
    fn read_by_id(&self, id: i64) -> Result<Option<Session>, HarnessError>;
    fn read_by_user_id(&self, user_id: i64) -> Result<Option<Session>, HarnessError>;
    fn insert(&self, session: &Session) -> Result<(), HarnessError>;
    fn delete(&self, id: i64) -> Result<(), HarnessError>;
}

pub trait DbHarnessToken {
    fn create_table(&self) -> Result<(), HarnessError>;
    fn insert(&self, token: &AuthToken) -> Result<(), HarnessError>;
    fn delete_access_token(&self, id: i64) -> Result<(), HarnessError>;
    fn delete_access_token_by_session(&self, session_id: i64) -> Result<(), HarnessError>;
    fn delete_resfresh_token(&self, id: i64) -> Result<(), HarnessError>;
    fn delete_refresh_token_by_session(&self, session_id: i64) -> Result<(), HarnessError>;
    fn read_refresh_token(&self, session_id: i64) -> Result<Option<AuthToken>, HarnessError>;
    fn read_access_token(&self, session_id: i64) -> Result<Option<AuthToken>, HarnessError>;
}

pub struct DbHarness<T, U, V>
where
    T: DbHarnessUser,
    U: DbHarnessSession,
    V: DbHarnessToken,
{
    pub user: T,
    pub session: U,
    pub token: V,
}

impl<T, U, V> DbHarness<T, U, V>
where
    T: DbHarnessUser,
    U: DbHarnessSession,
    V: DbHarnessToken,
{
    pub fn new_custom(user: T, session: U, token: V) -> Self {
        return Self {
            user,
            session,
            token,
        };
    }

    /// Function to initailize new tables in a database.
    pub fn init(self) -> Result<Self, HarnessError> {
        self.token.create_table()?;
        self.session.create_table()?;
        self.user.create_table()?;

        return Ok(self);
    }
}

impl<'a, T> DbHarness<T, StatelessSession, StatelessToken>
where
    T: DbHarnessUser,
{
    pub fn new_stateless(user_manager: T) -> Self {
        return DbHarness {
            user: user_manager,
            session: StatelessSession,
            token: StatelessToken,
        };
    }
}
