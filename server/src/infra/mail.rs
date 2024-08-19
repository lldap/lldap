use crate::infra::{cli::SmtpEncryption, configuration::MailOptions};
use anyhow::{anyhow, Ok, Result};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

async fn send_email(
    to: Mailbox,
    subject: &str,
    body: String,
    options: &MailOptions,
    server_url: &url::Url,
) -> Result<()> {
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
        .message_id(Some(format!(
            "<{}@{}>",
            uuid::Uuid::new_v1(
                uuid::Timestamp::now(uuid::NoContext),
                "lldap!".as_bytes().try_into().unwrap()
            ),
            server_url.domain().unwrap_or_default()
        )))
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
        SmtpEncryption::None => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&options.server)
        }
        SmtpEncryption::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&options.server)?,
        SmtpEncryption::StartTls => {
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

    if let Err(e) = mailer.port(options.port).build().send(email).await {
        debug!("Error sending email: {:?}", e);
        Err(anyhow!(
            "{}: SMTP error {}",
            if e.to_string().contains("CorruptMessage") {
                "CorruptMessage returned by lettre, this usually means the SMTP encryption setting is wrong"
            } else {
                "Error sending email"
            },
            e.status().map(|s| s.to_string()).unwrap_or_default()
        ))
    } else {
        Ok(())
    }
}

pub async fn send_password_reset_email(
    username: &str,
    to: &str,
    token: &str,
    server_url: &url::Url,
    options: &MailOptions,
) -> Result<()> {
    let to = to.parse()?;
    let mut reset_url = server_url.clone();
    reset_url
        .path_segments_mut()
        .unwrap()
        .extend(["reset-password", "step2", token]);
    let body = format!(
        "Hello {},
This email has been sent to you in order to validate your identity.
If you did not initiate the process your credentials might have been
compromised. You should reset your password and contact an administrator.

To reset your password please visit the following URL: {}

Please contact an administrator if you did not initiate the process.",
        username, reset_url
    );
    let res = send_email(
        to,
        "[LLDAP] Password reset requested",
        body,
        options,
        server_url,
    )
    .await;
    if res.is_err() {
        sleep(Duration::from_secs(3)).await;
    }
    res
}

pub async fn send_test_email(to: Mailbox, options: &MailOptions) -> Result<()> {
    send_email(
        to,
        "LLDAP test email",
        "The test is successful! You can send emails from LLDAP".to_string(),
        options,
        &url::Url::parse("http://localhost").unwrap(),
    )
    .await
}
