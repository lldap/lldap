use super::error::*;
use async_trait::async_trait;

pub use lldap_model::{login, registration};

#[async_trait]
pub trait OpaqueHandler: Clone + Send {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse>;
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<String>;
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
    async fn login_start(&self, request: login::ClientLoginStartRequest) -> Result<login::ServerLoginStartResponse>;
    async fn login_finish(&self, request: login::ClientLoginFinishRequest ) -> Result<String>;
    async fn registration_start(&self, request: registration::ClientRegistrationStartRequest) -> Result<registration::ServerRegistrationStartResponse>;
    async fn registration_finish(&self, request: registration::ClientRegistrationFinishRequest ) -> Result<()>;
    }
}
