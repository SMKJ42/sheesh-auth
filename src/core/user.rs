use std::net::IpAddr;

use crate::harness::{
    DbHarnessSession, DbHarnessToken, DbHarnessUser, DbHarnessUserExt, HarnessError,
};

use super::{
    auth_token::{AccessToken, RefreshToken},
    default_hash_fn, default_rng_salt_fn, default_verify_token_fn,
    id::{DefaultIdGenerator, IdGenerator},
    session::{Session, SessionManager},
    AuthError, AuthTokenError,
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
    ) -> Result<UserData, AuthError> {
        let id = self.id_generator.new_u64();

        let salt = (self.salt_fn)();
        let secret = (self.hash_fn)(&pwd, &salt)?;

        let user = UserData::new(i64::from_be_bytes(id.to_be_bytes()), username, secret, role);

        self.harness.insert(&user)?;
        return Ok(user);
    }

    /// Login
    pub fn login<Id, Sh, Th>(
        &self,
        session_manager: &SessionManager<Id, Sh, Th>,
        username: &str,
        pwd: &str,
        ip_addr: Option<IpAddr>,
    ) -> Result<(Session, RefreshToken, AccessToken), AuthError>
    where
        Id: IdGenerator,
        Sh: DbHarnessSession,
        Th: DbHarnessToken,
    {
        let user = if let Some(q_user) = self.get_user_by_username(username)? {
            q_user
        } else {
            return Err(AuthError::UserNotFound);
        };

        self.verify_pwd(&user, pwd)?;

        return session_manager.new_session(user.id, ip_addr);
    }

    pub fn logout<Id, Sh, Th>(
        &self,
        session_manager: &SessionManager<Id, Sh, Th>,
        user_id: i64,
        user_token_atmpt: &RefreshToken,
    ) -> Result<(), AuthError>
    where
        Id: IdGenerator,
        Sh: DbHarnessSession,
        Th: DbHarnessToken,
    {
        let session = session_manager.verify_refresh_token(user_id, user_token_atmpt)?;
        return Ok(session_manager.delete_session(session.id())?);
    }

    fn verify_pwd(&self, user: &UserData, pwd: &str) -> Result<(), AuthTokenError> {
        (self.verify_pass_fn)(pwd, &user.salted_hash())
    }

    pub fn update_user(&self, user: &UserData) -> Result<(), AuthError> {
        return Ok(self.harness.update(user)?);
    }

    pub fn update_password(&self, mut user: UserData, pwd: String) -> Result<(), AuthError> {
        let salt = (self.salt_fn)();
        let salted_hash = (self.hash_fn)(&pwd, &salt)?;

        user.set_salted_hash(salted_hash);

        return Ok(self
            .harness
            .update_salted_hash(user.id(), &user.salted_hash)?);
    }

    pub fn get_user_by_id(&self, id: &i64) -> Result<Option<UserData>, AuthError> {
        return Ok(self.harness.read_by_id(*id)?);
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<UserData>, AuthError> {
        return Ok(self.harness.read_by_username(username)?);
    }

    pub fn delete_user(&self, id: i64) -> Result<(), AuthError> {
        return Ok(self.harness.delete(id)?);
    }
}

impl<T, V> UserManager<T, V>
where
    T: IdGenerator,
    V: DbHarnessUserExt,
{
    /// Login
    pub fn login_log_on_fail<Id, Sh, Th>(
        &self,
        session_manager: &SessionManager<Id, Sh, Th>,
        username: &str,
        pwd: &str,
        ip_addr: Option<IpAddr>,
    ) -> Result<(Session, RefreshToken, AccessToken), AuthError>
    where
        Id: IdGenerator,
        Sh: DbHarnessSession,
        Th: DbHarnessToken,
    {
        let user = if let Some(q_user) = self.get_user_by_username(username)? {
            q_user
        } else {
            return Err(AuthError::UserNotFound);
        };

        let res = self.verify_pwd(&user, pwd);

        if res.is_err() {
            self.harness
                .set_attempts(user.id(), user.failed_attempts + 1)?;
        } else if user.failed_attempts != 0 {
            self.harness.set_attempts(user.id(), 0)?;
        }
        res?;

        return session_manager.new_session(user.id, ip_addr);
    }

    pub fn set_user_ban(&self, user_id: i64, ban: bool) -> Result<(), HarnessError> {
        return self.harness.set_ban(user_id, ban);
    }

    pub fn update_username(&self, user_id: i64, username: &str) -> Result<(), HarnessError> {
        return self.harness.update_username(user_id, username);
    }
}

#[derive(Clone, Debug)]
pub struct UserData {
    id: i64,
    username: String,
    salted_hash: String,
    is_banned: bool,
    groups: Groups,
    role: Role,
    failed_attempts: i64,
}

impl UserData {
    pub fn new(id: i64, username: String, salted_hash: String, role: Role) -> Self {
        return Self {
            id,
            username,
            salted_hash,
            is_banned: false,
            groups: Groups::new(),
            role,
            failed_attempts: 0,
        };
    }

    pub fn from_values(
        id: i64,
        username: String,
        salted_hash: String,
        is_banned: bool,
        groups: Groups,
        role: Role,
        failed_attempts: i64,
    ) -> Self {
        return Self {
            id,
            username,
            salted_hash,
            is_banned,
            groups,
            role,
            failed_attempts,
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
        return self.is_banned;
    }

    pub fn set_ban(&mut self, ban: bool) {
        self.is_banned = ban;
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

    pub fn remove_group(&mut self, group: Group) {
        self.groups.remove_group(group);
    }

    pub fn add_group(&mut self, group: Group) {
        self.groups.add_group(group);
    }

    pub fn incr_failed_attempt(&mut self) {
        self.failed_attempts += 1;
    }

    pub fn reset_failed_attempt(&mut self) {
        self.failed_attempts = 0;
    }

    pub fn failed_attempts(&self) -> i64 {
        return self.failed_attempts;
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
