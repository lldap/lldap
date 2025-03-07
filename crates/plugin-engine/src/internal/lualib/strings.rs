use mlua::{UserData, UserDataMethods};

use utf16string::{BigEndian, LittleEndian, WString};

#[derive(Clone, Debug)]
pub struct LuaStringsLib;

//
// String conversion utilities
//
impl UserData for LuaStringsLib {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("to_utf8", |_, _, s: String| Ok(s.into_bytes()));
        methods.add_method("to_utf16le", |_, _, s: String| {
            let ws: WString<LittleEndian> = WString::from(&s);
            Ok(ws.into_bytes())
        });
        methods.add_method("to_utf16be", |_, _, s: String| {
            let ws: WString<BigEndian> = WString::from(&s);
            Ok(ws.into_bytes())
        });
    }
}
