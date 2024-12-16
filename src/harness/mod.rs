pub mod mysql;
pub mod postgresql;
pub mod sqlite;

use std::{error, fmt::Display};

use crate::{
    auth_token::AuthToken,
    session::Session,
    user::{PrivateUserMeta, PublicUserMeta, UserMeta},
};

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
    fn read_by_id(&self, id: i64) -> Result<Option<UserMeta>, Box<dyn error::Error>>;
    fn read_by_username(&self, username: &str) -> Result<Option<UserMeta>, Box<dyn error::Error>>;
    fn update(&self, item: &UserMeta) -> Result<(), Box<dyn error::Error>>;
    fn set_ban(&self, id: i64, bool: bool) -> Result<(), Box<dyn error::Error>>;
    fn insert(&self, item: &UserMeta) -> Result<(), Box<dyn error::Error>>;
    fn delete(&self, id: i64) -> Result<(), Box<dyn error::Error>>;

    // fn write_role(&self) -> Result<(), Box<dyn error::Error>>;
    // fn insert_group(&self) -> Result<(), Box<dyn error::Error>>;
    // fn remove_group(&self) -> Result<(), Box<dyn error::Error>>;
    // // change signature to fn(pu: PublicUserMeta) -> SqlString ?
    // fn update_public(&self) -> Result<(), Box<dyn error::Error>>;
    // fn update_private(&self) -> Result<(), Box<dyn error::Error>>;
    // fn ban(&self) -> Result<(), Box<dyn error::Error>>;
}

pub trait DbHarnessSession {
    fn create_table(&self) -> Result<(), Box<dyn error::Error>>;
    fn read(&self, id: i64) -> Result<Session, Box<dyn error::Error>>;
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

pub fn repeat_vars(count: usize) -> String {
    assert_ne!(count, 0);
    let mut s = "?,".repeat(count);
    // Remove trailing comma
    s.pop();
    s
}

pub fn repeat_fields(cols: Vec<String>) -> String {
    let mut fields = String::new();
    for i in 0..cols.len() - 1 {
        fields.extend([&cols[i], ", "]);
    }
    fields += &cols[cols.len() - 1];

    return fields;
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
