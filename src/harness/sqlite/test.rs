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
        let conn_manager = SqliteConnectionManager::file("test_db/sqlite3.db");
        return r2d2::Pool::new(conn_manager).unwrap();
    }

    fn init_sqlite_config<'a>(
        pool: &'a Pool<SqliteConnectionManager>,
    ) -> (SqliteUserManager<'a>, SqliteSessionManager<'a>) {
        let harness = DbHarness::new_sqlite(&pool);

        harness.init_tables().unwrap();

        let user_manager = UserManagerConfig::default().init(harness.user);
        let session_manager = SessionManagerConfig::default().init(harness.session, harness.token);
        return (user_manager, session_manager);
    }

    fn obtain_session(session_manager: &SqliteSessionManager, user_id: i64) -> Session {
        return session_manager
            .get_session_by_user_id(user_id)
            .unwrap()
            .expect("No Session Found in DB");
    }

    #[test]
    fn token_validation() {
        let pool = init_pool();
        let (user_manager, session_manager) = init_sqlite_config(&pool);

        let username = "user_1".to_string();
        let pwd = "user_1_pwd".to_string();
        let role = Role::from_str("user");

        let user = user_manager
            .create_user(username, &pwd, role)
            .expect("Error creating user");

        let (user, refresh_token, access_token) = user_manager
            .login(&session_manager, &user.username(), &pwd, None)
            .expect("Error logging in user");

        let mut session = obtain_session(&session_manager, user.id());

        let access_token2 = session_manager
            .create_new_access_token(&mut session, user.id())
            .expect("Count not create new Access token");

        // clear the session's save state in memory and instead read it from the db...
        let mut session = obtain_session(&session_manager, user.id());

        // TODO: test access token validation...

        let (refresh_token3, access_token_3) = session_manager
            .create_new_refresh_token(&mut session, user.id())
            .expect("Could not create new Refresh token");

        // clear the session's save state in memory and instead read it from the db...
        let session = obtain_session(&session_manager, user.id());

        user_manager.delete_user(user.id()).unwrap();

        // TODO: test access and refresh token validation...
    }
}
