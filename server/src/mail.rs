use crate::{cli::SmtpEncryption, configuration::MailOptions};
use anyhow::{Context, Ok, Result, anyhow};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::Mailbox,
    transport::smtp::{
        authentication::Credentials,
        client::{Certificate, Tls, TlsParameters},
    },
};
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

/// Build TLS parameters trusting the extra certificate authority from the
/// config, if one was set. Returns None when no CA file is configured, in which
/// case lettre's default (system roots) is kept.
fn extra_ca_tls_parameters(options: &MailOptions) -> Result<Option<TlsParameters>> {
    let Some(ca_file) = options.certificate_authority_file.as_ref() else {
        return Ok(None);
    };
    let pem = std::fs::read(ca_file)
        .with_context(|| format!("Could not read SMTP certificate authority file '{ca_file}'"))?;
    let cert = Certificate::from_pem(&pem)
        .context("Could not parse the SMTP certificate authority file as PEM")?;
    let params = TlsParameters::builder(options.server.clone())
        .add_root_certificate(cert)
        .build()
        .context("Could not build the SMTP TLS parameters")?;
    Ok(Some(params))
}

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
        .from(from.0)
        .reply_to(reply_to.0)
        .to(to)
        .subject(subject)
        .singlepart(
            lettre::message::SinglePart::builder()
                .header(lettre::message::header::ContentType::TEXT_PLAIN)
                .body(body),
        )?;
    let extra_ca = extra_ca_tls_parameters(options)?;
    let mut mailer = match options.smtp_encryption {
        SmtpEncryption::None => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&options.server)
        }
        SmtpEncryption::Tls => {
            let builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&options.server)?;
            match extra_ca {
                Some(params) => builder.tls(Tls::Wrapper(params)),
                None => builder,
            }
        }
        SmtpEncryption::StartTls => {
            let builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&options.server)?;
            match extra_ca {
                Some(params) => builder.tls(Tls::Required(params)),
                None => builder,
            }
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
        let message = e.to_string();
        Err(anyhow!(
            "{}: {}",
            if message.contains("CorruptMessage")
                || message.contains("corrupt message")
                || message.contains("incomplete response")
            {
                "SMTP protocol error, this usually means the SMTP encryption setting is wrong. Try TLS with port 465 or STARTTLS with port 587"
            } else {
                "Error sending email"
            },
            message
        ))
    } else {
        Ok(())
    }
}

pub async fn send_password_reset_email(
    display_name: &str,
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
        "Hello {display_name},

Your username is: \"{username}\"

This email has been sent to you in order to validate your identity.
If you did not initiate the process your credentials might have been
compromised. You should reset your password and contact an administrator.

To reset your password please visit the following URL: {reset_url}

Please contact an administrator if you did not initiate the process."
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::MailOptions;
    use std::io::Write;

    // A self-signed CA certificate, only used to exercise the PEM parsing path.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIULE+qQttoolpaedinsO2J3juW1mUwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNTExEQVAgVGVzdCBDQTAeFw0yNjA4MjUwOTQ5MDdaFw0z
NjA4MjIwOTQ5MDdaMBgxFjAUBgNVBAMMDUxMREFQIFRlc3QgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4sprgzd6CD6ZrVPoiw+2gLJlbzMe02YPF
37SVPhOFAh2K+SuHokffj6SykKd+el1+9fa80EsIYHaaQzvdqbrpKkkXKxdaCGGE
U92q7gBxOTh1ydzYaXx9eNr1WYpF2c7OpJWcqnj0Xp5GQqbyKOwuwdMv2RtcEVs4
4pu7pgrOUmvz0LLM0ofJMp67yDp/cAUwhUnnRO9Kk7qgI98D3lj+tZQBz4u/pYSz
H/UXgcmydfDc+KWs1ed7jCcZTyZjPE+SuH4ro3C+w1/tXT5lHLPwN0vJ/dwVVwOG
dMmbxu9AwEIWhpgFcAQtzfHo2cFBT5bn2KgLrB7/+AGnOh5wR6/hAgMBAAGjUzBR
MB0GA1UdDgQWBBR3wmowg9aN/ty90pl5GQelMfTn9DAfBgNVHSMEGDAWgBR3wmow
g9aN/ty90pl5GQelMfTn9DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQAncU5M+9rfAxdSja5ugsDiz6hWFUb1CA3WaQ3LvSRroqPR6Aw+DBgzclv4
4nfSm9PVSdr8QBtxqfBV1nXt/6N43htanftNJ5qbwg8+5w0eQ35kLyn3v0oxEklw
4fRN6P8WAEp5pBKiD91lyn6cNoXu97fD+HJL0mYcwnGTcVKqb+b9NNS5Pl1bODkt
r5YLd7YyFhAuVxg/fifCUkCGgrylvszUA7qBG+anLddFWrPfyIXFTCoU6ZHGlot+
mfMfJnLiA+NtYwZd3ADUJIFxrchURfneghSUe2jy9ZIxATP8gp3gVdNrZcX8Ro09
XDG2Yh1OF/z9HU65Swk7B6mG6HDe
-----END CERTIFICATE-----
";

    fn options_with_ca(ca_file: Option<String>) -> MailOptions {
        MailOptions {
            certificate_authority_file: ca_file,
            ..Default::default()
        }
    }

    struct TempPem(std::path::PathBuf);
    impl TempPem {
        fn new(name: &str, contents: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("lldap_test_{}_{}", std::process::id(), name));
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(contents.as_bytes()).unwrap();
            TempPem(path)
        }
        fn path(&self) -> String {
            self.0.to_str().unwrap().to_string()
        }
    }
    impl Drop for TempPem {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn no_ca_file_keeps_default_tls() {
        let options = options_with_ca(None);
        assert!(extra_ca_tls_parameters(&options).unwrap().is_none());
    }

    #[test]
    fn valid_ca_file_builds_parameters() {
        let pem = TempPem::new("valid_ca.pem", TEST_CA_PEM);
        let options = options_with_ca(Some(pem.path()));
        assert!(extra_ca_tls_parameters(&options).unwrap().is_some());
    }

    #[test]
    fn missing_ca_file_is_an_error() {
        let options = options_with_ca(Some("/does/not/exist/ca.pem".to_string()));
        assert!(extra_ca_tls_parameters(&options).is_err());
    }
}
