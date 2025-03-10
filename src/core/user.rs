use std::{error, fmt::Display};

use crate::harness::{DbHarnessSession, DbHarnessToken, DbHarnessUser};

use super::{
    auth_token::{AuthTokenError, TokenManagerError},
    default_hash_fn, default_rng_salt_fn, default_verify_token_fn,
    id::{DefaultIdGenerator, IdGenerator},
    session::{AccessSecret, RefreshSecret, SessionManager},
};

pub struct UserManagerConfig<T>
where
    T: IdGenerator,
{
    id_generator: T,
    salt_fn: fn() -> String,
    hash_fn: fn(&str, &str) -> Result<String, AuthTokenError>,
    verify_pass_fn: fn(&str, &str) -> Result<(), AuthTokenError>,
}

impl UserManagerConfig<DefaultIdGenerator> {
    pub fn default() -> Self {
        Self {
            id_generator: DefaultIdGenerator {},
            salt_fn: default_rng_salt_fn,
            hash_fn: default_hash_fn,
            verify_pass_fn: default_verify_token_fn,
        }
    }
}

impl<T: IdGenerator> UserManagerConfig<T> {
    pub fn new(
        id_generator: T,
        salt_fn: fn() -> String,
        hash_fn: fn(&str, &str) -> Result<String, AuthTokenError>,
        verify_pass_fn: fn(&str, &str) -> Result<(), AuthTokenError>,
    ) -> Self {
        return Self {
            id_generator,
            salt_fn,
            hash_fn,
            verify_pass_fn,
        };
    }
}

impl<T> UserManagerConfig<T>
where
    T: IdGenerator + Copy,
{
    pub fn init<V: DbHarnessUser>(&self, harness: V) -> UserManager<T, V> {
        UserManager {
            id_generator: self.id_generator,
            hash_fn: self.hash_fn,
            verify_pass_fn: self.verify_pass_fn,
            salt_fn: self.salt_fn,
            harness,
        }
    }

    pub fn with_id_gen<X: IdGenerator + Copy>(&self, id_generator: X) -> UserManagerConfig<X> {
        return UserManagerConfig {
            id_generator,
            salt_fn: self.salt_fn,
            verify_pass_fn: self.verify_pass_fn,
            hash_fn: self.hash_fn,
        };
    }
}

pub struct UserManager<T, V>
where
    T: IdGenerator,
    V: DbHarnessUser,
{
    id_generator: T,
    harness: V,
    salt_fn: fn() -> String,
    hash_fn: fn(&str, &str) -> Result<String, AuthTokenError>,
    verify_pass_fn: fn(&str, &str) -> Result<(), AuthTokenError>,
}

impl<T, V> UserManager<T, V>
where
    T: IdGenerator,
    V: DbHarnessUser,
{
    /// Write a new user to the database. Uses a random salt to secure the password field.
    pub fn create_user(
        &self,
        username: String,
        pwd: &str,
        role: Role,
    ) -> Result<UserData, UserManagerError> {
        let id = self.id_generator.new_u64();

        let salt = (self.salt_fn)();
        let secret = (self.hash_fn)(&pwd, &salt)?;

        let user = UserData::new(i64::from_be_bytes(id.to_be_bytes()), username, secret, role)?;

        self.harness.insert(&user)?;
        return Ok(user);
    }

    /// Login
    pub fn login<Id, Sh, Th>(
        &self,
        session_manager: &SessionManager<Id, Sh, Th>,
        username: &str,
        pwd: &str,
    ) -> Result<(UserData, RefreshSecret, AccessSecret), UserManagerError>
    where
        Id: IdGenerator,
        Sh: DbHarnessSession,
        Th: DbHarnessToken,
    {
        let mut user: UserData;

        match self.get_user_by_username(username)? {
            None => return Err(UserManagerError::new(UserManagerErrorKind::UserNotFound)),
            Some(q_user) => {
                // assign user, continue to verify password
                user = q_user;
            }
        };

        self.verify_pwd(&user, pwd)?;

        let (session, refresh, access) = session_manager.new_session(user.id)?;

        user.session_id = Some(session.id());
        self.update_user(&user)?;

        return Ok((user, refresh, access));
    }

    pub fn logout<Id, Sh, Th>(
        &self,
        session_manager: &SessionManager<Id, Sh, Th>,
        user: &UserData,
        user_token_atmpt: &str,
    ) -> Result<(), UserManagerError>
    where
        Id: IdGenerator,
        Sh: DbHarnessSession,
        Th: DbHarnessToken,
    {
        // if the user has a session...
        if let Some(session_id) = user.session_id {
            // fetch the session from the database, if the session exists...
            if let Some(session) = session_manager.get_session_by_id(session_id)? {
                match session.refresh_token() {
                    // and the refresh token exists...
                    Some(refresh_token_id) => {
                        // ensure that the user has the authority to logout. If they do not, we will early return, and the session will remain valid.
                        session_manager.verify_session_token(
                            refresh_token_id,
                            user.id,
                            user_token_atmpt,
                        )?;
                    }
                    None => {
                        /*
                         * user is already logged out, but we still want to ensure the access token is invalidated.
                         * This is safe because the state of this branch would be
                         *
                         * Session {
                         *     refresh_token: None
                         *     access_token: Option<token_id>
                         * }
                         *
                         * Invalidating the session if the session does not have a refresh token is intended behavior.
                         */
                    }
                }
                session_manager.invalidate_session(session)?;

                return Ok(());
            } else {
                return Err(UserManagerError::new(
                    UserManagerErrorKind::AlreadyLoggedOut,
                ));
            }
        } else {
            return Err(UserManagerError::new(
                UserManagerErrorKind::AlreadyLoggedOut,
            ));
        };
    }

    fn verify_pwd(&self, user: &UserData, pwd: &str) -> Result<(), AuthTokenError> {
        (self.verify_pass_fn)(pwd, &user.salted_hash())
    }

    pub fn update_user(&self, user: &UserData) -> Result<(), Box<dyn error::Error>> {
        return self.harness.update(user);
    }

    pub fn update_password(
        &self,
        mut user: UserData,
        pwd: String,
    ) -> Result<(), Box<dyn error::Error>> {
        let salt = (self.salt_fn)();
        let salted_hash = (self.hash_fn)(&pwd, &salt)?;

        user.set_salted_hash(salted_hash);

        return self.harness.update_salted_hash(user.id(), user.salted_hash);
    }

    pub fn get_user_by_id(&self, id: &i64) -> Result<Option<UserData>, Box<dyn error::Error>> {
        return self.harness.read_by_id(*id);
    }

    pub fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserData>, Box<dyn error::Error>> {
        return self.harness.read_by_username(username);
    }

    pub fn delete_user(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        return self.harness.delete(id);
    }
}

#[derive(Clone, Debug)]
pub struct UserData {
    id: i64,
    session_id: Option<i64>,
    username: String,
    salted_hash: String,
    ban: bool,
    groups: Groups,
    role: Role,
}

impl UserData {
    pub fn new(
        id: i64,
        username: String,
        salted_hash: String,
        role: Role,
    ) -> Result<Self, Box<dyn error::Error>> {
        return Ok(Self {
            id,
            username,
            salted_hash,
            ban: false,
            session_id: None,
            groups: Groups::new(),
            role,
        });
    }

    pub fn from_values(
        id: i64,
        session_id: Option<i64>,
        username: String,
        salted_hash: String,
        ban: bool,
        groups: Groups,
        role: Role,
    ) -> Self {
        return Self {
            id,
            session_id,
            username,
            salted_hash,
            ban,
            groups,
            role,
        };
    }

    pub fn id(&self) -> i64 {
        return self.id;
    }

    pub fn username(&self) -> &str {
        return &self.username;
    }

    pub fn set_username(&mut self, username: String) {
        self.username = username;
    }

    pub fn salted_hash(&self) -> &str {
        return &self.salted_hash;
    }

    fn set_salted_hash(&mut self, salted_hash: String) {
        self.salted_hash = salted_hash;
    }

    pub fn is_banned(&self) -> bool {
        return self.ban;
    }

    pub fn ban(&mut self) {
        self.ban = true;
    }

    pub fn unban(&mut self) {
        self.ban = false;
    }

    pub fn groups(&self) -> &Groups {
        return &self.groups;
    }

    pub fn role(&self) -> &Role {
        return &self.role;
    }

    pub fn set_role(&mut self, role: Role) {
        self.role = role;
    }

    pub fn session_id(&self) -> Option<i64> {
        return self.session_id;
    }

    pub fn remove_group(&mut self, group: Group) {
        self.groups.remove_group(group);
    }

    pub fn add_group(&mut self, group: Group) {
        self.groups.add_group(group);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Role {
    pub name: String,
}

impl Role {
    pub fn from_string(name: String) -> Self {
        return Self { name };
    }

    pub fn from_str(name: &str) -> Self {
        return Self {
            name: name.to_owned(),
        };
    }

    pub fn as_str(&self) -> &str {
        return self.name.as_str();
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct Group {
    name: String,
}

impl Group {
    pub fn from_string(name: String) -> Self {
        return Self { name };
    }

    pub fn from_str(name: &str) -> Self {
        return Self {
            name: name.to_owned(),
        };
    }

    pub fn as_str(&self) -> &str {
        return self.name.as_str();
    }
}

impl IntoIterator for Groups {
    type Item = Group;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.groups.into_iter()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Groups {
    groups: Vec<Group>,
}

impl Groups {
    pub fn new() -> Self {
        return Self { groups: Vec::new() };
    }

    pub fn from_vec(groups: Vec<Group>) -> Self {
        return Self { groups };
    }
}

impl Groups {
    pub fn contains(&self, group: Group) -> bool {
        return self.groups.contains(&group);
    }

    pub fn add_group(&mut self, group: Group) {
        for c_group in &self.groups {
            if *c_group == group {
                return;
            }
        }
        self.groups.push(group);
    }

    pub fn remove_group(&mut self, group: Group) {
        let mut idx = 0;
        for c_group in &self.groups {
            if *c_group == group {
                return;
            }
            idx += 1;
        }

        self.groups.remove(idx);
    }

    pub fn to_string(&self) -> String {
        let mut string = String::new();

        for group in &self.groups {
            string += group.as_str()
        }

        return string;
    }
}

pub trait PublicUserData: Clone {}

pub trait PrivateUserData: Clone {}

#[derive(Debug)]
pub enum UserManagerErrorKind {
    // Error can be in the harness, or in the token validation. This will occure only after the user and token are verified and the logout fails.
    SessionInvalidation(TokenManagerError),
    AlreadyLoggedOut,
    // Error resides strictly in the Token, not in the harness.
    Token(AuthTokenError),
    Harness(Box<dyn error::Error>),
    UserNotFound,
}

impl From<TokenManagerError> for UserManagerError {
    fn from(value: TokenManagerError) -> Self {
        match value {
            TokenManagerError::AuthToken(err) => Self::new(UserManagerErrorKind::Token(err)),
            TokenManagerError::Harness(err) => Self::new(UserManagerErrorKind::Harness(err)),
        }
    }
}

#[derive(Debug)]
pub struct UserManagerError {
    pub kind: UserManagerErrorKind,
}

impl Display for UserManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "{}", self);
    }
}

impl From<Box<dyn error::Error>> for UserManagerError {
    fn from(value: Box<dyn error::Error>) -> Self {
        return UserManagerError::new(UserManagerErrorKind::Harness(value));
    }
}

impl From<AuthTokenError> for UserManagerError {
    fn from(value: AuthTokenError) -> Self {
        return UserManagerError::new(UserManagerErrorKind::Token(value));
    }
}

impl UserManagerError {
    pub fn new(kind: UserManagerErrorKind) -> Self {
        return Self { kind };
    }

    pub fn kind(&self) -> &UserManagerErrorKind {
        return &self.kind;
    }
}

impl error::Error for UserManagerError {}
