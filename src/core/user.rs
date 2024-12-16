use std::{error, fmt::Display};

use crate::harness::{DbHarnessSession, DbHarnessToken, DbHarnessUser};

use super::{
    auth_token::{AuthTokenError, TokenManagerError},
    default_hash_fn, default_rng_salt_fn, default_verify_token_fn,
    id::{DefaultIdGenerator, IdGenerator},
    session::{AccessSecret, RefreshSecret, Session, SessionManager},
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
    pub fn create_user(
        &self,
        username: String,
        pwd: String,
        role: Role,
    ) -> Result<UserMeta, UserManagerError> {
        let id = self.id_generator.new_u64();

        let salt = (self.salt_fn)();
        let secret = (self.hash_fn)(&pwd, &salt)?;

        let user = UserMeta::new(i64::from_be_bytes(id.to_be_bytes()), username, secret, role)?;

        self.harness.insert(&user)?;
        return Ok(user);
    }

    pub fn login<Id, Sh, Th>(
        &self,
        session_manager: &SessionManager<Id, Sh, Th>,
        username: &str,
        pwd: &str,
    ) -> Result<(Session, RefreshSecret, AccessSecret), UserManagerError>
    where
        Id: IdGenerator,
        Sh: DbHarnessSession,
        Th: DbHarnessToken,
    {
        let user_res = self.get_user_by_username(username);
        let user: UserMeta;

        match user_res {
            // harness error occured, propogate the err.
            Err(err) => return Err(err.into()),
            Ok(user_opt) => match user_opt {
                // user not found
                None => return Err(UserManagerError::new(UserManagerErrorKind::UserNotFound)),
                Some(q_user) => {
                    // assign user, continue to verify password
                    user = q_user;
                }
            },
        }

        match self.verify_pwd(&user, pwd) {
            // Error validating the user, propogate the Error.
            Err(err) => return Err(err.into()),
            Ok(_) => {
                let sess_res = session_manager.new_session(user.id);
                match sess_res {
                    Ok(res) => return Ok(res),
                    Err(err) => return Err(err.into()),
                }
            }
        };
    }

    pub fn logout<Id, Sh, Th>(
        &self,
        session_manager: &SessionManager<Id, Sh, Th>,
        user: &UserMeta,
        user_token_atmpt: &str,
    ) -> Result<(), UserManagerError>
    where
        Id: IdGenerator,
        Sh: DbHarnessSession,
        Th: DbHarnessToken,
    {
        match user.session_id {
            Some(session_id) => match session_manager.get_session(session_id) {
                Ok(session) => {
                    match session.refresh_token() {
                        Some(refresh_token_id) => {
                            // ensure that the user has the authority to logout -- they have a valid session token
                            match session_manager.verify_session_token(
                                refresh_token_id,
                                user.id,
                                user_token_atmpt,
                            ) {
                                // token was verified.
                                Ok(()) => return Ok(()),
                                // token was invalid.
                                Err(err) => return Err(err.into()),
                            }
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
                             * We cannot have an access token without a refresh token, and .invalidate_session() will handle flipping the access_token to None.
                             *
                             * alternatively we could use unreachable!(), but I dont like the idea of a authentication server panicing.
                             */
                        }
                    }
                    match session_manager.invalidate_session(session) {
                        Ok(()) => return Ok(()),
                        Err(err) => {
                            return Err(UserManagerError::new(
                                UserManagerErrorKind::SessionInvalidation(err),
                            ))
                        }
                    }
                }
                Err(err) => return Err(UserManagerError::new(UserManagerErrorKind::Harness(err))),
            },
            None => {
                return Err(UserManagerError::new(
                    UserManagerErrorKind::AlreadyLoggedOut,
                ))
            }
        }
    }

    pub fn verify_pwd(&self, user: &UserMeta, pwd: &str) -> Result<(), AuthTokenError> {
        (self.verify_pass_fn)(pwd, &user.secret)
    }

    pub fn update_user(&self, user: UserMeta) -> Result<(), Box<dyn error::Error>> {
        return self.harness.update(&user);
    }

    pub fn update_password(
        &self,
        mut user: UserMeta,
        pwd: String,
    ) -> Result<(), Box<dyn error::Error>> {
        let salt = (self.salt_fn)();
        let secret = (self.hash_fn)(&pwd, &salt)?;

        user.set_secret(secret);

        return self.harness.update(&user);
    }

    pub fn get_user_by_id(&self, id: &i64) -> Result<Option<UserMeta>, Box<dyn error::Error>> {
        return self.harness.read_by_id(*id);
    }

    pub fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserMeta>, Box<dyn error::Error>> {
        return self.harness.read_by_username(username);
    }

    pub fn delete_user(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        return self.harness.delete(id);
    }
}

#[derive(Clone)]
pub struct UserMeta {
    id: i64,
    session_id: Option<i64>,
    username: String,
    secret: String,
    ban: bool,
    groups: Groups,
    role: Role,
    // public: Option<Pu>,
    // private: Option<Pr>,
}

impl UserMeta {
    pub fn new(
        id: i64,
        username: String,
        secret: String,
        role: Role,
    ) -> Result<Self, Box<dyn error::Error>> {
        return Ok(Self {
            id,
            username,
            secret,
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
        secret: String,
        ban: bool,
        groups: Groups,
        role: Role,
    ) -> Self {
        return Self {
            id,
            session_id,
            username,
            secret,
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

    pub fn secret(&self) -> &str {
        return &self.secret;
    }

    fn set_secret(&mut self, secret: String) {
        self.secret = secret;
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

#[derive(Clone, Debug)]
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

pub trait PublicUserMeta: Clone {}

pub trait PrivateUserMeta: Clone {}

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
}

impl error::Error for UserManagerError {}
