use mlua::{Result as LuaResult, Table};

pub fn bytes_from_table(table: &Table) -> LuaResult<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for v in table.sequence_values::<u8>().into_iter() {
        bytes.push(v?);
    }
    Ok(bytes)
}
