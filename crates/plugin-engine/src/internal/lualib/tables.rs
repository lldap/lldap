use mlua::{Result as LuaResult, Table, UserData, UserDataMethods, Value};

#[derive(Clone, Debug)]
pub struct LuaTablesLib;

//
// String conversion utilities
//
impl UserData for LuaTablesLib {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("eq", |_, _, (a, b): (Table, Table)| table_equals(&a, &b));
        methods.add_method("has_subtree", |_, _, (base, tree): (Table, Table)| {
            table_has_tree(&base, &tree)
        });
        methods.add_method("empty", |_, _, t: Table| Ok(t.len()? == 0));
    }
}

fn table_equals(a: &Table, b: &Table) -> LuaResult<bool> {
    if a.len()? != b.len()? {
        return Ok(false);
    }
    for pair in a.pairs::<Value, Value>() {
        let (key, value) = pair?;
        if !b.contains_key(key.clone())? {
            return Ok(false);
        }
        let bval: Value = b.get(key)?;
        if !value.type_name().eq_ignore_ascii_case(bval.type_name()) {
            return Ok(false);
        }
        if value.is_table() {
            if !table_equals(value.as_table().unwrap(), bval.as_table().unwrap())? {
                return Ok(false);
            }
        } else {
            if !value.equals(&bval)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn table_has_tree(base: &Table, tree: &Table) -> LuaResult<bool> {
    let mut result: bool = true;
    for pair in tree.pairs::<Value, Value>() {
        let mut elem_result: bool = false;
        let (key, value) = pair?;
        if base.contains_key(&key)? {
            let bval: Value = base.get(key)?;
            if value.type_name().eq_ignore_ascii_case(bval.type_name()) {
                if value.is_table() {
                    elem_result =
                        table_has_tree(value.as_table().unwrap(), bval.as_table().unwrap())?;
                } else {
                    if value.equals(&bval)? {
                        elem_result = true
                    }
                }
            }
        }
        result = result && elem_result;
    }
    // meh
    Ok(true)
}
