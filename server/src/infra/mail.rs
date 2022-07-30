use crate::infra::{cli::SmtpEncryption, configuration::MailOptions};
use anyhow::Result;
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, Message, SmtpTransport,
    Transport,
};
use tracing::debug;

fn send_email(to: Mailbox, subject: &str, body: String, options: &MailOptions) -> Result<()> {
    let from = options
        .from
        .clone()
        .unwrap_or_else(|| "LLDAP <nobody@lldap>".parse().unwrap());
    let reply_to = options.reply_to.clone().unwrap_or_else(|| from.clone());
    debug!(
        "Sending email to '{}' as '{}' via '{}'@'{}':'{}'",
        &to, &from, &options.user, &options.server, options.port
    );
    let email = Message::builder()
        .from(from)
        .reply_to(reply_to)
        .to(to)
        .subject(subject)
        .body(body)?;
    let creds = Credentials::new(
        options.user.clone(),
        options.password.unsecure().to_string(),
    );
    let relay_factory = match options.smtp_encryption {
        SmtpEncryption::TLS => SmtpTransport::relay,
        SmtpEncryption::STARTTLS => SmtpTransport::starttls_relay,
    };
    let mailer = relay_factory(&options.server)?.credentials(creds).build();
    mailer.send(&email)?;
    Ok(())
}

pub fn send_password_reset_email(
    username: &str,
    to: &str,
    token: &str,
    domain: &str,
    options: &MailOptions,
) -> Result<()> {
    let to = to.parse()?;
    let body = format!(
        "Hello {},
This email has been sent to you in order to validate your identity.
If you did not initiate the process your credentials might have been
compromised. You should reset your password and contact an administrator.

To reset your password please visit the following URL: {}/reset-password/step2/{}

Please contact an administrator if you did not initiate the process.",
        username, domain, token
    );
    send_email(to, "[LLDAP] Password reset requested", body, options)
}

pub fn send_test_email(to: Mailbox, options: &MailOptions) -> Result<()> {
    send_email(
        to,
        "LLDAP test email",
        "The test is successful! You can send emails from LLDAP".to_string(),
        options,
    )
}
