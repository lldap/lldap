use lldap_domain::types::{MFA_TYPE_TOTP, UserId};
use lldap_domain_handlers::handler::MfaPolicy;
use lldap_domain_model::error::Result;

use crate::UserReadableBackendHandler;

pub const MFA_ENROLLMENT_REQUIRED: &str =
    "MFA enrollment required: enroll through the web interface or contact an administrator";

pub struct MfaEnrollmentStatus {
    pub enrolled: bool,
    pub exempt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaRequirement {
    None,
    Totp,
    Enrollment,
}

pub async fn mfa_enrollment_status(
    handler: &impl UserReadableBackendHandler,
    user_id: &UserId,
) -> Result<MfaEnrollmentStatus> {
    let enrolled =
        handler.get_user_details(user_id).await?.mfa_type.as_deref() == Some(MFA_TYPE_TOTP);
    let exempt = handler
        .get_user_groups(user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_mfa_disabled".into());
    Ok(MfaEnrollmentStatus { enrolled, exempt })
}

// `status` is None for unknown users, who keep the unauthenticated behaviour.
pub fn mfa_requirement(policy: MfaPolicy, status: Option<&MfaEnrollmentStatus>) -> MfaRequirement {
    match (policy, status) {
        (MfaPolicy::Disabled, _) | (_, None) => MfaRequirement::None,
        (_, Some(status)) if status.exempt => MfaRequirement::None,
        (_, Some(status)) if status.enrolled => MfaRequirement::Totp,
        (MfaPolicy::Enrolled, _) => MfaRequirement::None,
        (MfaPolicy::Always, _) => MfaRequirement::Enrollment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(enrolled: bool, exempt: bool) -> MfaEnrollmentStatus {
        MfaEnrollmentStatus { enrolled, exempt }
    }

    #[test]
    fn test_mfa_requirement() {
        let policies = [MfaPolicy::Disabled, MfaPolicy::Enrolled, MfaPolicy::Always];
        for policy in policies {
            assert_eq!(mfa_requirement(policy, Option::None), MfaRequirement::None);
        }
        for enrolled in [false, true] {
            for exempt in [false, true] {
                assert_eq!(
                    mfa_requirement(MfaPolicy::Disabled, Some(&status(enrolled, exempt))),
                    MfaRequirement::None
                );
            }
        }
        for policy in [MfaPolicy::Enrolled, MfaPolicy::Always] {
            for enrolled in [false, true] {
                assert_eq!(
                    mfa_requirement(policy, Some(&status(enrolled, true))),
                    MfaRequirement::None
                );
            }
            assert_eq!(
                mfa_requirement(policy, Some(&status(true, false))),
                MfaRequirement::Totp
            );
        }
        assert_eq!(
            mfa_requirement(MfaPolicy::Enrolled, Some(&status(false, false))),
            MfaRequirement::None
        );
        assert_eq!(
            mfa_requirement(MfaPolicy::Always, Some(&status(false, false))),
            MfaRequirement::Enrollment
        );
    }
}
