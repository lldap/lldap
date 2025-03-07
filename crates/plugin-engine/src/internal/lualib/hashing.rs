use mlua::{Result as LuaResult, Table, UserData, UserDataMethods};

use digest::Digest;
use md4::Md4;
use md5::Md5;
use sha2::{Sha256, Sha512};

use crate::internal::lualib::utils;

#[derive(Clone, Debug)]
pub struct LuaHashingLib;

impl UserData for LuaHashingLib {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        //
        // Hashing utilities
        //
        methods.add_method("md4_hash_bytes", |_, _, btable: Table| {
            Ok(hash_bytes::<Md4>(&btable)?)
        });
        methods.add_method("md5_hash_bytes", |_, _, btable: Table| {
            Ok(hash_bytes::<Md5>(&btable)?)
        });
        methods.add_method("sha256_hash_bytes", |_, _, btable: Table| {
            Ok(hash_bytes::<Sha256>(&btable)?)
        });
        methods.add_method("sha512_hash_bytes", |_, _, btable: Table| {
            Ok(hash_bytes::<Sha512>(&btable)?)
        });
    }
}

fn hash_bytes<D: Digest>(table: &Table) -> LuaResult<Vec<u8>> {
    let bytes = utils::bytes_from_table(table)?;
    let mut hasher = D::new();
    hasher.update(bytes);
    Ok(hasher.finalize().as_slice().to_vec())
}
