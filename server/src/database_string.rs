use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Serialize, Deserialize, derive_more::Display)]
#[display("{_0}")]
pub struct DatabaseUrl(Url);

impl From<Url> for DatabaseUrl {
    fn from(url: Url) -> Self {
        Self(url)
    }
}

impl From<&str> for DatabaseUrl {
    fn from(url: &str) -> Self {
        Self(Url::parse(url).expect("Invalid database URL"))
    }
}

impl DatabaseUrl {
    pub fn db_type(&self) -> &str {
        self.0.scheme()
    }
}

impl std::fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.password().is_some() {
            let mut url = self.0.clone();
            // It can fail for URLs that cannot have a password, like "mailto:bob@example".
            let _ = url.set_password(Some("***PASSWORD***"));
            f.write_fmt(format_args!(r#""{url}""#))
        } else {
            f.write_fmt(format_args!(r#""{}""#, self.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_url_debug() {
        let url = DatabaseUrl::from("postgres://user:pass@localhost:5432/dbname");
        assert_eq!(
            format!("{url:?}"),
            r#""postgres://user:***PASSWORD***@localhost:5432/dbname""#
        );
        assert_eq!(
            url.to_string(),
            "postgres://user:pass@localhost:5432/dbname"
        );
    }
}
