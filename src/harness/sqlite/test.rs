#[cfg(test)]
mod core_test {
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    use crate::{
        harness::{
            sqlite::{
                session::SqliteHarnessSession, token::SqliteHarnessToken, user::SqliteHarnessUser,
            },
            DbHarness,
        },
        id::DefaultIdGenerator,
        session::{Session, SessionManager, SessionManagerConfig},
        user::{Role, UserManager, UserManagerConfig},
    };

    type SqliteUserManager<'a> = UserManager<DefaultIdGenerator, SqliteHarnessUser<'a>>;
    type SqliteSessionManager<'a> =
        SessionManager<DefaultIdGenerator, SqliteHarnessSession<'a>, SqliteHarnessToken<'a>>;

    fn init_pool() -> Pool<SqliteConnectionManager> {
        let conn_manager = SqliteConnectionManager::file("test_db/sqlite3.db").with_init(|conn| {
            conn.execute("PRAGMA foreign_keys = ON;", [])?;
            Ok(())
        });
        return r2d2::Pool::new(conn_manager).unwrap();
    }

    fn init_sqlite_config<'a>(
        pool: &'a Pool<SqliteConnectionManager>,
    ) -> (SqliteUserManager<'a>, SqliteSessionManager<'a>) {
        let harness = DbHarness::new_sqlite(&pool).init().unwrap();
        let user_manager = UserManagerConfig::default().init(harness.user);
        let session_manager = SessionManagerConfig::default().init(harness.session, harness.token);
        return (user_manager, session_manager);
    }

    fn obtain_session(session_manager: &SqliteSessionManager, session_id: i64) -> Session {
        return session_manager
            .get_session_by_id(session_id)
            .unwrap()
            .expect("No Session Found in DB");
    }

    #[test]
    fn token_validation() {
        /*
         * Project Init.
         */
        let pool = init_pool();
        let (user_manager, session_manager) = init_sqlite_config(&pool);

        let username = "user_1".to_string();
        let pwd = "user_1_pwd".to_string();
        let role = Role::from_str("user");

        /*
         * User login
         */

        let user = user_manager
            .create_user(username, &pwd, role)
            .expect("Error creating user");

        let (session, _refresh_token, access_token) = user_manager
            .login(&session_manager, &user.username(), &pwd, None)
            .expect("Error logging in user");

        /*
         * Access Tokens.
         */

        let access_token2 = session_manager
            .create_new_access_token(&session)
            .expect("Count not create new Access token");

        session_manager
            .verify_access_token(session.id(), &access_token2)
            .expect("Failed to authenticate access token.");

        // ensure that the access token did in fact change.
        assert_ne!(access_token, access_token2);

        /*
         * Refresh Tokens.
         */

        // clear the session's save state in memory and instead read it from the db...
        let session = obtain_session(&session_manager, session.id());

        let (refresh_token3, access_token3) = session_manager
            .create_new_refresh_token(&session)
            .expect("Could not create new Refresh token");

        session_manager
            .verify_access_token(session.id(), &access_token3)
            .expect("Failed to authenticate access token.");

        session_manager
            .verify_refresh_token(session.id(), &refresh_token3)
            .expect("Failed to authenticate refresh token.");

        // It is implied that a refresh token grants a new access token, so test to make sure that the access token has changed.
        assert_ne!(access_token2, access_token3);

        // clear the session's save state in memory and instead read it from the db...
        let session = obtain_session(&session_manager, session.id());

        /*
         * User cleanup...
         */

        user_manager.delete_user(user.id()).unwrap();

        assert_eq!(
            session_manager.get_session_by_id(session.id()).unwrap(),
            None
        );

        assert!(session_manager
            .verify_access_token(session.id(), &access_token3)
            .is_err());

        assert!(session_manager
            .verify_refresh_token(session.id(), &refresh_token3)
            .is_err())
    }
}
