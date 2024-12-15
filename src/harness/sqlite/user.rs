use std::{error, result};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;

use crate::{
    harness::DbHarnessUser,
    user::{PrivateUserMeta, PublicUserMeta, User},
};

pub struct SqliteHarnessUser {
    connection: Pool<SqliteConnectionManager>,
    private_cols: Vec<&'static str>,
    public_cols: Vec<&'static str>,
}

impl SqliteHarnessUser {
    pub fn new(connection: Pool<SqliteConnectionManager>) -> Self {
        Self {
            connection,
            private_cols: Vec::new(),
            public_cols: Vec::new(),
        }
    }

    pub fn with_public_cols(mut self, cols: Vec<&'static str>) -> Self {
        self.public_cols = cols;
        return self;
    }

    pub fn with_private_cols(mut self, cols: Vec<&'static str>) -> Self {
        self.private_cols = cols;
        return self;
    }
}

impl DbHarnessUser for SqliteHarnessUser {
    fn delete(&self, id: i64) -> Result<(), Box<dyn error::Error>> {
        self.connection
            .get()?
            .prepare("DELETE FROM users WHERE id = ?")?
            .execute([id])?;
        return Ok(());
    }

    fn insert<Pu, Pr>(&self, user: &User<Pu, Pr>) -> Result<(), Box<dyn error::Error>>
    where
        Pu: PublicUserMeta,
        Pr: PrivateUserMeta,
    {
        let my_params: String;
        let my_named_params: String;
        if self.public_cols.len() == 0 && self.private_cols.len() == 0 {
            my_params = String::new();
            my_named_params = String::new();
        } else {
            todo!();
        }

        //TODO: dynamically utilize the fields in the .public_meta and .private_meta
        self.connection.get()?.execute(
            format!(
                "INSERT INTO users (id, session_id, username, secret, ban, groups, role{})
                    VALUES (:id, :session_id, :username, :secret, :ban, :groups, :role{})",
                my_params, my_named_params
            )
            .as_str(),
            named_params! {
                ":id": user.id(),
                ":session_id": user.session_id(),
                ":username": user.username(),
                ":secret": user.secret(),
                ":ban": user.is_banned(),
                ":groups": user.groups(),
                ":role": user.role()
            },
        )?;

        return Ok(());
    }
    fn read<Pu, Pr>(&self, id: i64) -> Result<Option<User<Pu, Pr>>, Box<dyn error::Error>>
    where
        Pu: PublicUserMeta,
        Pr: PrivateUserMeta,
    {
        let conn = self.connection.get()?;
        let res = conn.query_row("SELECT * FROM users WHERE id = ?", [id], |row| {
            let id = row.get(0)?;
            let session_id = row.get(1)?;
            let username = row.get(2)?;
            let secret = row.get(3)?;
            let ban = row.get(4)?;
            let groups = row.get(5)?;
            let role = row.get(6)?;

            return Ok(User::from_values(
                id, session_id, username, secret, ban, groups, role, None, None,
            ));
        });

        match res {
            Ok(user) => Ok(Some(user)),
            Err(err) => Err(err.into()),
        }
    }
    fn update<Pu, Pr>(&self, user: &User<Pu, Pr>) -> Result<usize, Box<dyn error::Error>>
    where
        Pu: PublicUserMeta,
        Pr: PrivateUserMeta,
    {
        let conn = self.connection.get()?;
        let res = conn.execute(
            "UPDATE users SET 
        session_id = :session_id,
        username = :username,
        ban = :ban,
        groups = :groups,
        role = :role
        WHERE id = :id",
            named_params! {
                ":id": user.id(),
                ":session_id": user.session_id(),
                ":username": user.username(),
                ":ban": user.is_banned(),
                ":groups": user.groups(),
                ":role": user.role()
            },
        );

        match res {
            Ok(res) => Ok(res),
            Err(err) => Err(err.into()),
        }
    }

    fn create_table(
        &self,
        sql_string: Option<String>,
    ) -> result::Result<(), Box<dyn error::Error>> {
        let default_stmt = format!(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                session_id INTEGER,
                username STRING NOT NULL UNIQUE,
                secret STRING NOT NULL,
                ban TINYINT NOT NULL,
                groups STRING NOT NULL,
                role STRING NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            "
        );

        match sql_string {
            Some(stmt_extension) => {
                self.connection
                    .get()?
                    .prepare(format!("{},{});", default_stmt, stmt_extension).as_str())?
                    .execute([])?;
            }
            None => {
                self.connection
                    .get()?
                    .prepare(format!("{});", default_stmt).as_str())?
                    .execute([])?;
            }
        };

        return Ok(());
    }

    // fn ban(&self) -> result::Result<(), Box<dyn error::Error>> {
    //     todo!()
    // }

    // fn insert_group(&self) -> result::Result<(), Box<dyn error::Error>> {
    //     todo!()
    // }

    // fn remove_group(&self) -> result::Result<(), Box<dyn error::Error>> {
    //     todo!()
    // }

    // fn update_private(&self) -> result::Result<(), Box<dyn error::Error>> {
    //     todo!()
    // }

    // fn update_public(&self) -> result::Result<(), Box<dyn error::Error>> {
    //     todo!()
    // }

    // fn write_role(&self) -> result::Result<(), Box<dyn error::Error>> {
    //     todo!()
    // }
}
