use std::fmt::Display;

use sheesh::user::{PrivateUserMeta, PublicUserMeta, Role, UserMeta};

// the following trait impls create type safety for you across the application.
pub enum Roles {
    Admin,
}

impl Roles {
    pub fn to_string(&self) -> String {
        match self {
            Self::Admin => return String::from("admin"),
        }
    }

    pub fn as_role(&self) -> Role {
        return Role::from_string(self.to_string());
    }
}

impl Display for Roles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => {
                write!(f, "admin")
            }
        }
    }
}
#[derive(Clone)]
pub struct MyPublicUserMetadata;
impl PublicUserMeta for MyPublicUserMetadata {
    // fn from_values(values: &mut slice::Iter<'_, String>) -> Option<Self> {
    //     None
    // }
    // fn into_values(&self) -> Vec<String> {
    //     vec![]
    // }
}

#[derive(Clone)]
pub struct MyPrivateUserMetadata;
impl PrivateUserMeta for MyPrivateUserMetadata {
    // fn from_values(values: &mut slice::Iter<'_, String>) -> Option<Self> {
    //     None
    // }
    // fn into_values(&self) -> Vec<String> {
    //     vec![]
    // }
}
