use std::env;

use r2d2_sqlite::SqliteConnectionManager;
use sheesh::{harness::stateless::init_stateless_sqlite_config, user::Role};

/// The Stateless example is usefull for authentication schemes where a
/// session is based on a long lived connection.
///
/// It would NOT be suitable for something like HTTP where the connection is droped after serving the response.

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(0).expect("No file path provided.");

    // Initialize the database connection and wrap it in an r2d2 pool
    let conn = SqliteConnectionManager::file(path);
    let pool = r2d2::Pool::new(conn).unwrap();

    // Initialize tables, and the handlers that allow access to the authentication database.
    let (user_manager, session_manager) = init_stateless_sqlite_config(pool);

    // Provide new user params.
    let username = "user_1".to_string();
    let pwd = "user_1_pwd".to_string();
    let role = Role::from_str("user");

    // Create a new user.
    let user = user_manager
        .create_user(username.clone(), &pwd, role)
        .expect("Error creating user");

    // Log in a user with a username and password.
    // Optionally you can add an IP address for handling sessions.
    let _ = user_manager
        .login(&session_manager, &user.username(), &pwd, None)
        .expect("Error logging in user");

    // User is logged in!
}
