use base64ct::{Base64, Encoding};
use mlua::{Table, UserData, UserDataMethods};

use crate::internal::lualib::utils;

#[derive(Clone, Debug)]
pub struct LuaEncodingLib;

impl UserData for LuaEncodingLib {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        //
        // Encoding utilities
        //
        methods.add_method("base64_encode", |_, _, btable: Table| {
            let bytes = utils::bytes_from_table(&btable)?;
            Ok(Base64::encode_string(bytes.as_slice()))
        });
        methods.add_method(
            "base64_decode",
            |_, _, s: String| match Base64::decode_vec(s.as_str()) {
                Ok(bytes) => Ok(bytes),
                Err(_) => Err(mlua::Error::FromLuaConversionError {
                    from: "<base64 encoded string>",
                    to: "String".to_string(),
                    message: Some("Invalid base64 encoded string".to_string()),
                }),
            },
        );
        methods.add_method("base16_encode", |_, _, btable: Table| {
            let bytes = utils::bytes_from_table(&btable)?;
            Ok(base16ct::lower::encode_string(&bytes))
        });
    }
}
