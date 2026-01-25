use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Options {
    pub password_reset_enabled: bool,
    pub password_policy: PasswordPolicyOptions,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PasswordPolicyOptions {
    pub min_length: usize,
    pub min_uppercase: usize,
    pub min_lowercase: usize,
    pub min_digits: usize,
    pub min_special: usize,
    pub allowed_specials: Vec<char>,
}

impl Default for PasswordPolicyOptions {
    fn default() -> Self {
        Self {
            min_length: 8,
            min_uppercase: 0,
            min_lowercase: 0,
            min_digits: 0,
            min_special: 0,
            allowed_specials: vec!['!', '@', '#', '$', '%', '^', '&', '*'],
        }
    }
}

pub fn validate_password(password: &str, policy: &PasswordPolicyOptions) -> Result<()> {
    let mut errors = Vec::new();

    if password.len() < policy.min_length {
        errors.push(format!(
            "Password must be at least {} characters long.",
            policy.min_length
        ));
    }

    let mut uppercase = 0;
    let mut lowercase = 0;
    let mut digits = 0;
    let mut special = 0;

    for c in password.chars() {
        if c.is_uppercase() {
            uppercase += 1;
        } else if c.is_lowercase() {
            lowercase += 1;
        } else if c.is_ascii_digit() {
            digits += 1;
        } else if policy.allowed_specials.contains(&c) {
            special += 1;
        }
    }

    if uppercase < policy.min_uppercase {
        errors.push(format!(
            "Password must contain at least {} uppercase characters.",
            policy.min_uppercase
        ));
    }

    if lowercase < policy.min_lowercase {
        errors.push(format!(
            "Password must contain at least {} lowercase characters.",
            policy.min_lowercase
        ));
    }

    if digits < policy.min_digits {
        errors.push(format!(
            "Password must contain at least {} digit(s).",
            policy.min_digits
        ));
    }

    if special < policy.min_special {
        errors.push(format!(
            "Password must contain at least {} special character(s) from: {}",
            policy.min_special,
            policy
                .allowed_specials
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        // join all messages into one big error string, or handle Vec<String> upstream
        bail!("{}", errors.join("\n"));
    }
}
