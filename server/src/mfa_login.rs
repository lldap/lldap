use actix_web::web;
use lldap_access_control::{MfaRequirement, mfa_enrollment_status, mfa_requirement};
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::{BackendHandler, MfaPolicy};
use lldap_domain_model::error::DomainError;
use lldap_mfa::{TOTP_CODE_ALREADY_USED, TOTP_TOO_MANY_ATTEMPTS, TotpFailure, totp_failure};
use tracing::warn;

use crate::{
    tcp_backend_handler::TcpBackendHandler,
    tcp_server::{AppState, TcpResult},
};

// A replayed code or a spent allowance may be named: the password was verified by
// then. Anything else stays generic, to not reveal which factor failed.
pub(crate) fn totp_error(e: DomainError) -> DomainError {
    let message = match totp_failure(&e.to_string()) {
        TotpFailure::Replayed => TOTP_CODE_ALREADY_USED,
        TotpFailure::TooManyAttempts => TOTP_TOO_MANY_ATTEMPTS,
        TotpFailure::Other => "Invalid credentials",
    };
    DomainError::AuthenticationError(message.to_owned())
}

// Never skip MFA because the status could not be read.
pub(crate) async fn get_mfa_requirement<Backend>(
    data: &web::Data<AppState<Backend>>,
    user: &UserId,
) -> TcpResult<MfaRequirement>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    if data.mfa_policy == MfaPolicy::Disabled {
        return Ok(MfaRequirement::None);
    }
    let status = match mfa_enrollment_status(data.get_readonly_handler(), user).await {
        Ok(status) => Some(status),
        // Unknown users bind as before, and fail there.
        Err(DomainError::EntityNotFound(_)) => None,
        Err(e) => {
            warn!("Could not read the MFA status, refusing the login: {:#}", e);
            return Err(DomainError::AuthenticationError("Invalid credentials".to_owned()).into());
        }
    };
    Ok(mfa_requirement(data.mfa_policy, status.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_error() {
        assert!(matches!(
            totp_error(DomainError::AuthenticationError(format!(
                "{TOTP_CODE_ALREADY_USED} for bob"
            ))),
            DomainError::AuthenticationError(m) if m == TOTP_CODE_ALREADY_USED
        ));
        assert!(matches!(
            totp_error(DomainError::AuthenticationError("wrong code".to_owned())),
            DomainError::AuthenticationError(m) if m == "Invalid credentials"
        ));
        assert!(matches!(
            totp_error(DomainError::InternalError("db down".to_owned())),
            DomainError::AuthenticationError(m) if m == "Invalid credentials"
        ));
    }
}
