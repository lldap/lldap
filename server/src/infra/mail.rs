use crate::infra::configuration::MailOptions;
use anyhow::Result;
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, Message, SmtpTransport,
    Transport,
};
use log::debug;

pub fn send_test_email(to: Mailbox, options: &MailOptions) -> Result<()> {
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
        .subject("LLDAP test email")
        .body("The test is successful! You can send emails from LLDAP".to_string())?;
    let creds = Credentials::new(
        options.user.clone(),
        options.password.unsecure().to_string(),
    );
    let mailer = SmtpTransport::relay(&options.server)?
        .credentials(creds)
        .build();
    mailer.send(&email)?;
    Ok(())
}
