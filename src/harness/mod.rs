pub mod mysql;
pub mod postgresql;
pub mod sqlite;
pub mod stateless;

use std::{error, fmt::Display};

use crate::{auth_token::AuthToken, session::Session, user::UserData};

pub enum Db {
    MySql,
    Postgresql,
    Sqlite,
}

#[derive(Debug)]
pub struct HarnessError(Box<dyn error::Error>);

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
    fn create_table(&self) -> Result<(), Box<dyn error::Error>>;
    fn read_by_id(&self, id: i64) -> Result<Option<UserData>, Box<dyn error::Error>>;
    fn read_by_username(&self, username: &str) -> Result<Option<UserData>, Box<dyn error::Error>>;
    // A helper function to update username, groups and role in one function.
    fn update(&self, item: &UserData) -> Result<(), Box<dyn error::Error>>;
    // A function to update the session_id, calling .update() will not update this field.
    fn update_session_id(
        &self,
        user_id: i64,
        session_id: Option<i64>,
    ) -> Result<(), Box<dyn error::Error>>;
    // A function to update the salted_hash, calling .update() will not update this field.
    fn update_salted_hash(&self, id: i64, salted_hash: String)
        -> Result<(), Box<dyn error::Error>>;
    // A function to update the ban, calling .update() will not update this field.
    fn update_ban(&self, id: i64, bool: bool) -> Result<(), Box<dyn error::Error>>;
    fn insert(&self, item: &UserData) -> Result<(), Box<dyn error::Error>>;
    fn delete(&self, id: i64) -> Result<(), Box<dyn error::Error>>;
}

pub trait DbHarnessSession {
    fn create_table(&self) -> Result<(), Box<dyn error::Error>>;
    fn read_by_id(&self, user_id: i64) -> Result<Option<Session>, Box<dyn error::Error>>;
    fn read_by_user_id(&self, id: i64) -> Result<Option<Session>, Box<dyn error::Error>>;
    fn update(&self, session: &Session) -> Result<(), Box<dyn error::Error>>;
    fn insert(&self, session: &Session) -> Result<(), Box<dyn error::Error>>;
    fn delete(&self, id: i64) -> Result<(), Box<dyn error::Error>>;
}

pub trait DbHarnessToken {
    fn create_table(&self) -> Result<(), Box<dyn error::Error>>;
    fn update(&self, token: &AuthToken) -> Result<(), Box<dyn error::Error>>;
    fn insert(&self, token: &AuthToken) -> Result<(), Box<dyn error::Error>>;
    fn delete_access_token(&self, id: i64) -> Result<(), Box<dyn error::Error>>;
    fn delete_resfresh_token(&self, id: i64) -> Result<(), Box<dyn error::Error>>;
    fn read_refresh_token(&self, id: i64) -> Result<Option<AuthToken>, Box<dyn error::Error>>;
    fn read_access_token(&self, id: i64) -> Result<Option<AuthToken>, Box<dyn error::Error>>;
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

    pub fn init_tables(&self) -> Result<(), HarnessError> {
        self.token.create_table()?;
        self.session.create_table()?;
        self.user.create_table()?;

        return Ok(());
    }
}
