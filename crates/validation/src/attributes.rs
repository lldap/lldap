// Description of allowed characters. Intended for error messages.
pub const ALLOWED_CHARACTERS_DESCRIPTION: &str = "a-z, A-Z, 0-9, and dash (-)";

pub fn validate_attribute_name(attribute_name: &str) -> Result<(), Vec<char>> {
    let invalid_chars: Vec<char> = attribute_name
        .chars()
        .filter(|c| !(c.is_alphanumeric() || *c == '-'))
        .collect();
    if invalid_chars.is_empty() {
        Ok(())
    } else {
        Err(invalid_chars)
    }
}

mod tests {

    #[test]
    fn test_valid_attribute_name() {
        let valid1: String = "AttrName-01".to_string();
        let result = super::validate_attribute_name(&valid1);
        assert!(result == Ok(()));
    }

    #[test]
    fn test_invalid_attribute_name_chars() {
        fn test_invalid_char(c: char) {
            let prefix: String = "AttrName".to_string();
            let suffix: String = "01".to_string();
            let name: String = format!("{prefix}{c}{suffix}");
            let result = super::validate_attribute_name(&name);
            match result {
                Ok(()) => {
                    panic!()
                }
                Err(invalid) => {
                    assert!(invalid == vec![c.to_owned()]);
                }
            }
        }
        test_invalid_char(' ');
        test_invalid_char('_');
        test_invalid_char('#');
    }
}
