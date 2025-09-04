use lldap_sql_backend_handler::password_service::PasswordVerificationService;
use lldap_auth::opaque::server::generate_random_private_key;
use lldap_domain::types::UserId;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    println!("Testing password verification service...");

    let service = PasswordVerificationService::new();

    // Create a test opaque setup
    let opaque_setup = lldap_auth::opaque::server::ServerSetup::new(&generate_random_private_key());

    // Test with dummy data (this should fail, but shouldn't panic)
    let dummy_password_file = vec![1, 2, 3, 4];
    let clear_password = "testpassword";
    let username = UserId::new("testuser");

    let result = service.verify_password(
        &dummy_password_file,
        clear_password,
        &opaque_setup,
        &username,
    ).await;

    match result {
        Ok(_) => println!("Verification succeeded (unexpected)"),
        Err(e) => println!("Verification failed as expected: {:?}", e),
    }

    println!("Password verification service test completed!");
}
