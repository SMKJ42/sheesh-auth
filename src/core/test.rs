#[cfg(test)]
mod core_test {
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    use crate::{
        default_hash_fn, default_rng_salt_fn, default_verify_token_fn,
        harness::stateless::init_stateless_sqlite_config, user::Role,
    };

    fn init_pool() -> Pool<SqliteConnectionManager> {
        let conn_manager = SqliteConnectionManager::file("test_db/core.db");
        return r2d2::Pool::new(conn_manager).unwrap();
    }

    #[test]
    fn salt_and_hash_then_verify() {
        let pwd = "This is a password";
        let salt = default_rng_salt_fn();

        let hash =
            default_hash_fn(pwd, &salt).expect("Error when trying to salt and hash password");

        default_verify_token_fn(pwd, &hash)
            .expect("Error trying to verify a password against it's salted hash");
    }

    #[test]
    fn user_login() {
        let pool = init_pool();
        let (user_manager, session_manager) = init_stateless_sqlite_config(&pool).unwrap();

        let username = "user_1".to_string();
        let pwd = "user_1_pwd".to_string();
        let role = Role::from_str("user");

        let user = user_manager
            .create_user(username.clone(), &pwd, role)
            .expect("Error creating user");

        let (_session, refresh_token, access_token) = user_manager
            .login(&session_manager, &user.username(), &pwd, None)
            .expect("Error logging in user");

        assert_eq!(refresh_token, "");
        assert_eq!(access_token, "");

        assert_ne!(user.salted_hash(), pwd);
        assert_eq!(user.username(), username);
        assert_eq!(user.role().as_str(), "user");

        user_manager.delete_user(user.id()).unwrap();
    }
}
