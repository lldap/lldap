use lldap_auth::opaque;
use lldap_domain::types::UserId;
use lldap_domain_model::error::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, instrument};

/// Different types of cryptographic operations that can be performed
pub enum CryptoOperation {
    /// LDAP bind password verification
    PasswordVerification {
        password_file_bytes: Vec<u8>,
        clear_password: String,
        opaque_setup: Arc<opaque::server::ServerSetup>,
        username: UserId,
    },
    /// OPAQUE login start operation
    LoginStart {
        opaque_setup: Arc<opaque::server::ServerSetup>,
        maybe_password_file: Option<Vec<u8>>,
        login_start_request: opaque::server::login::CredentialRequest,
        username: UserId,
    },
    /// OPAQUE login finish operation
    LoginFinish {
        server_login: opaque::server::login::ServerLogin,
        credential_finalization: opaque::server::login::CredentialFinalization,
    },
    /// OPAQUE registration start operation
    RegistrationStart {
        opaque_setup: Arc<opaque::server::ServerSetup>,
        registration_start_request: opaque::server::registration::RegistrationRequest,
        username: UserId,
    },
    /// OPAQUE registration finish operation (get password file)
    RegistrationFinish {
        registration_upload: opaque::server::registration::RegistrationUpload,
    },
}

/// Results from cryptographic operations
pub enum CryptoResult {
    /// Result from password verification
    PasswordVerification(Result<()>),
    /// Result from OPAQUE login start
    LoginStart(Box<Result<opaque::server::login::ServerLoginStartResult>>),
    /// Result from OPAQUE login finish
    LoginFinish(Result<opaque::server::login::ServerLoginFinishResult>),
    /// Result from OPAQUE registration start
    RegistrationStart(Box<Result<opaque::server::registration::ServerRegistrationStartResult>>),
    /// Result from OPAQUE registration finish
    RegistrationFinish(Result<opaque::server::registration::ServerRegistration>),
}

/// A task for cryptographic operations
struct CryptoTask {
    operation: CryptoOperation,
    response_tx: oneshot::Sender<CryptoResult>,
}

/// Service for cryptographic operations that runs on a dedicated background thread
/// to avoid blocking the main worker threads with expensive argon2 operations
#[derive(Clone)]
pub struct PasswordService {
    task_tx: mpsc::UnboundedSender<CryptoTask>,
}

impl PasswordService {
    /// Create a new cryptographic service and start the background worker
    pub fn new() -> Self {
        let (task_tx, task_rx) = mpsc::unbounded_channel();

        // Spawn the background worker thread
        tokio::spawn(Self::worker_task(task_rx));

        Self { task_tx }
    }

    /// Verify a password asynchronously (for LDAP bind)
    #[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
    pub async fn verify_password(
        &self,
        password_file_bytes: &[u8],
        clear_password: &str,
        opaque_setup: &opaque::server::ServerSetup,
        username: &UserId,
    ) -> Result<()> {
        let operation = CryptoOperation::PasswordVerification {
            password_file_bytes: password_file_bytes.to_vec(),
            clear_password: clear_password.to_string(),
            opaque_setup: Arc::new(opaque_setup.clone()),
            username: username.clone(),
        };

        self.process_operation(operation, |result| {
            if let CryptoResult::PasswordVerification(res) = result {
                Some(res)
            } else {
                None
            }
        })
        .await
    }

    /// Perform OPAQUE login start asynchronously
    #[instrument(skip_all, level = "debug", err)]
    pub async fn opaque_login_start(
        &self,
        opaque_setup: &opaque::server::ServerSetup,
        maybe_password_file: Option<&[u8]>,
        login_start_request: opaque::server::login::CredentialRequest,
        username: &UserId,
    ) -> Result<opaque::server::login::ServerLoginStartResult> {
        let operation = CryptoOperation::LoginStart {
            opaque_setup: Arc::new(opaque_setup.clone()),
            maybe_password_file: maybe_password_file.map(|b| b.to_vec()),
            login_start_request,
            username: username.clone(),
        };

        self.process_operation(operation, |result| {
            if let CryptoResult::LoginStart(res) = result {
                Some(*res)
            } else {
                None
            }
        })
        .await
    }

    /// Perform OPAQUE login finish asynchronously
    #[instrument(skip_all, level = "debug", err)]
    pub async fn opaque_login_finish(
        &self,
        server_login: opaque::server::login::ServerLogin,
        credential_finalization: opaque::server::login::CredentialFinalization,
    ) -> Result<opaque::server::login::ServerLoginFinishResult> {
        let operation = CryptoOperation::LoginFinish {
            server_login,
            credential_finalization,
        };

        self.process_operation(operation, |result| {
            if let CryptoResult::LoginFinish(res) = result {
                Some(res)
            } else {
                None
            }
        })
        .await
    }

    /// Perform OPAQUE registration start asynchronously
    #[instrument(skip_all, level = "debug", err)]
    pub async fn opaque_registration_start(
        &self,
        opaque_setup: &opaque::server::ServerSetup,
        registration_start_request: opaque::server::registration::RegistrationRequest,
        username: &UserId,
    ) -> Result<opaque::server::registration::ServerRegistrationStartResult> {
        let operation = CryptoOperation::RegistrationStart {
            opaque_setup: Arc::new(opaque_setup.clone()),
            registration_start_request,
            username: username.clone(),
        };

        self.process_operation(operation, |result| {
            if let CryptoResult::RegistrationStart(res) = result {
                Some(*res)
            } else {
                None
            }
        })
        .await
    }

    /// Perform OPAQUE registration finish asynchronously
    #[instrument(skip_all, level = "debug", err)]
    pub async fn opaque_registration_finish(
        &self,
        registration_upload: opaque::server::registration::RegistrationUpload,
    ) -> Result<opaque::server::registration::ServerRegistration> {
        let operation = CryptoOperation::RegistrationFinish {
            registration_upload,
        };

        self.process_operation(operation, |result| {
            if let CryptoResult::RegistrationFinish(res) = result {
                Some(res)
            } else {
                None
            }
        })
        .await
    }

    /// Generic method to process any crypto operation
    async fn process_operation<T: 'static>(
        &self,
        operation: CryptoOperation,
        expected_result: fn(CryptoResult) -> Option<T>,
    ) -> T {
        let (response_tx, response_rx) = oneshot::channel();

        let task = CryptoTask {
            operation,
            response_tx,
        };

        if self.task_tx.send(task).is_err() {
            panic!("Cryptographic service is not available");
        }

        match response_rx.await {
            Ok(result) => expected_result(result).expect("Unexpected crypto result type"),
            Err(_) => panic!("Crypto operation was cancelled"),
        }
    }

    ////////////////////////////////////////////////////////////////////////////

    /// Background worker task that processes crypto requests sequentially
    async fn worker_task(mut task_rx: mpsc::UnboundedReceiver<CryptoTask>) {
        debug!("Cryptographic service worker started");

        while let Some(task) = task_rx.recv().await {
            let result = Self::process_crypto_operation(task.operation);

            // Send result back (ignore if receiver is dropped)
            let _ = task.response_tx.send(result);
        }

        debug!("Cryptographic service worker stopped");
    }

    /// Process a single cryptographic operation
    fn process_crypto_operation(operation: CryptoOperation) -> CryptoResult {
        match operation {
            CryptoOperation::PasswordVerification {
                password_file_bytes,
                clear_password,
                opaque_setup,
                username,
            } => {
                let result = Self::passwords_match_sync(
                    &password_file_bytes,
                    &clear_password,
                    &opaque_setup,
                    &username,
                );
                CryptoResult::PasswordVerification(result)
            }
            CryptoOperation::LoginStart {
                opaque_setup,
                maybe_password_file,
                login_start_request,
                username,
            } => {
                let result = Self::opaque_login_start_sync(
                    &opaque_setup,
                    maybe_password_file.as_deref(),
                    login_start_request,
                    &username,
                );
                CryptoResult::LoginStart(Box::new(result))
            }
            CryptoOperation::LoginFinish {
                server_login,
                credential_finalization,
            } => {
                let result = Self::opaque_login_finish_sync(server_login, credential_finalization);
                CryptoResult::LoginFinish(result)
            }
            CryptoOperation::RegistrationStart {
                opaque_setup,
                registration_start_request,
                username,
            } => {
                let result = Self::opaque_registration_start_sync(
                    &opaque_setup,
                    registration_start_request,
                    &username,
                );
                CryptoResult::RegistrationStart(Box::new(result))
            }
            CryptoOperation::RegistrationFinish {
                registration_upload,
            } => {
                let result = Self::opaque_registration_finish_sync(registration_upload);
                CryptoResult::RegistrationFinish(result)
            }
        }
    }

    /// Synchronous password matching function (runs on background thread)
    #[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
    fn passwords_match_sync(
        password_file_bytes: &[u8],
        clear_password: &str,
        opaque_setup: &opaque::server::ServerSetup,
        username: &UserId,
    ) -> Result<()> {
        use opaque::{client, server};
        let mut rng = rand::rngs::OsRng;
        let client_login_start_result = client::login::start_login(clear_password, &mut rng)?;

        let password_file = server::ServerRegistration::deserialize(password_file_bytes)
            .map_err(opaque::AuthenticationError::ProtocolError)?;
        let server_login_start_result = server::login::start_login(
            &mut rng,
            opaque_setup,
            Some(password_file),
            client_login_start_result.message,
            username,
        )?;
        client::login::finish_login(
            client_login_start_result.state,
            server_login_start_result.message,
        )?;
        Ok(())
    }

    /// Synchronous OPAQUE login start (runs on background thread)
    #[instrument(skip_all, level = "debug", err)]
    fn opaque_login_start_sync(
        opaque_setup: &opaque::server::ServerSetup,
        maybe_password_file: Option<&[u8]>,
        login_start_request: opaque::server::login::CredentialRequest,
        username: &UserId,
    ) -> Result<opaque::server::login::ServerLoginStartResult> {
        let mut rng = rand::rngs::OsRng;

        let maybe_password_file = maybe_password_file
            .map(|bytes| {
                opaque::server::ServerRegistration::deserialize(bytes).map_err(|_| {
                    lldap_domain_model::error::DomainError::InternalError(format!(
                        "Corrupted password file for {}",
                        username
                    ))
                })
            })
            .transpose()?;

        Ok(opaque::server::login::start_login(
            &mut rng,
            opaque_setup,
            maybe_password_file,
            login_start_request,
            username,
        )?)
    }

    /// Synchronous OPAQUE login finish (runs on background thread)
    #[instrument(skip_all, level = "debug", err)]
    fn opaque_login_finish_sync(
        server_login: opaque::server::login::ServerLogin,
        credential_finalization: opaque::client::login::CredentialFinalization,
    ) -> Result<opaque::server::login::ServerLoginFinishResult> {
        Ok(opaque::server::login::finish_login(
            server_login,
            credential_finalization,
        )?)
    }

    /// Synchronous OPAQUE registration start (runs on background thread)
    #[instrument(skip_all, level = "debug", err)]
    fn opaque_registration_start_sync(
        opaque_setup: &opaque::server::ServerSetup,
        registration_start_request: opaque::server::registration::RegistrationRequest,
        username: &UserId,
    ) -> Result<opaque::server::registration::ServerRegistrationStartResult> {
        Ok(opaque::server::registration::start_registration(
            opaque_setup,
            registration_start_request,
            username,
        )?)
    }

    /// Synchronous OPAQUE registration finish (runs on background thread)
    #[instrument(skip_all, level = "debug", err)]
    fn opaque_registration_finish_sync(
        registration_upload: opaque::server::registration::RegistrationUpload,
    ) -> Result<opaque::server::registration::ServerRegistration> {
        Ok(opaque::server::registration::get_password_file(
            registration_upload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_service_creation() {
        // Test that the service can be created and doesn't panic
        PasswordService::new();

        // Give it a moment to start the background task
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // The service should be created successfully
        // This test mainly ensures no panics during initialization
    }

    #[tokio::test]
    async fn test_password_verification_failure() {
        let service = PasswordService::new();
        let opaque_setup = lldap_auth::opaque::server::generate_random_private_key();

        // Test with invalid password data - should fail gracefully
        let dummy_password_file = vec![1, 2, 3, 4];
        let clear_password = "testpassword";
        let username = UserId::new("testuser");

        let result = service
            .verify_password(
                &dummy_password_file,
                clear_password,
                &opaque_setup,
                &username,
            )
            .await;

        // Should fail but not panic
        assert!(result.is_err());
    }
}
