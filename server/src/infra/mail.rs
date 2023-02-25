use crate::infra::{cli::SmtpEncryption, configuration::MailOptions};
use anyhow::{Ok, Result};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use tracing::debug;

async fn send_email(to: Mailbox, subject: &str, body: String, options: &MailOptions) -> Result<()> {
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
        .singlepart(
            lettre::message::SinglePart::builder()
                .header(lettre::message::header::ContentType::TEXT_PLAIN)
                .body(body),
        )?;
    let mut mailer = match options.smtp_encryption {
        SmtpEncryption::NONE => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&options.server)
        }
        SmtpEncryption::TLS => AsyncSmtpTransport::<Tokio1Executor>::relay(&options.server)?,
        SmtpEncryption::STARTTLS => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&options.server)?
        }
    };
    if options.user.as_str() != "" {
        let creds = Credentials::new(
            options.user.clone(),
            options.password.unsecure().to_string(),
        );
        mailer = mailer.credentials(creds)
    }

    mailer.port(options.port).build().send(email).await?;
    Ok(())
}

pub async fn send_password_reset_email(
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
        username,
        domain.trim_end_matches('/'),
        token
    );
    send_email(to, "[LLDAP] Password reset requested", body, options).await
}

pub async fn send_test_email(to: Mailbox, options: &MailOptions) -> Result<()> {
    send_email(
        to,
        "LLDAP test email",
        "The test is successful! You can send emails from LLDAP".to_string(),
        options,
    )
    .await
}
