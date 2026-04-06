use async_trait::async_trait;
use lldap_domain::types::UserId;
use lldap_domain_model::error::Result;

pub use lldap_auth::{login, login_base64, registration};

#[async_trait]
pub trait OpaqueHandler: Send + Sync {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse>;
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId>;
    /// Legacy (opaque-ke 0.7) login start. Used for progressive migration
    /// when a user's stored password is still in the old format.
    async fn login_start_legacy(
        &self,
        request: login_base64::ClientLoginStartRequest,
    ) -> Result<login_base64::ServerLoginStartResponse>;
    /// Legacy (opaque-ke 0.7) login finish. On success, the caller should
    /// re-register the password in the new format to complete the migration.
    async fn login_finish_legacy(
        &self,
        request: login_base64::ClientLoginFinishRequest,
    ) -> Result<UserId>;
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse>;
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()>;
}

#[cfg(test)]
mockall::mock! {
    pub TestOpaqueHandler{}
    impl Clone for TestOpaqueHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl OpaqueHandler for TestOpaqueHandler {
        async fn login_start(
            &self,
            request: login::ClientLoginStartRequest
        ) -> Result<login::ServerLoginStartResponse>;
        async fn login_finish(&self, request: login::ClientLoginFinishRequest ) -> Result<UserId>;
        async fn login_start_legacy(
            &self,
            request: login_base64::ClientLoginStartRequest
        ) -> Result<login_base64::ServerLoginStartResponse>;
        async fn login_finish_legacy(
            &self,
            request: login_base64::ClientLoginFinishRequest
        ) -> Result<UserId>;
        async fn registration_start(
            &self,
            request: registration::ClientRegistrationStartRequest
        ) -> Result<registration::ServerRegistrationStartResponse>;
        async fn registration_finish(
            &self,
            request: registration::ClientRegistrationFinishRequest
        ) -> Result<()>;
    }
}
