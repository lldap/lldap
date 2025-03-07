use lldap_domain::types::{AttributeName, GroupDetails, GroupId, UserId};

use mlua::{Lua, LuaSerdeExt, Table, UserData, UserDataMethods};

use crate::{
    api::backend::BackendAPI,
    internal::{
        context::parameters::{
            create_attribute::CreateAttributeParams, create_group::CreateGroupParams,
            create_user::CreateUserParams, list_groups::ListGroupsLdapFilterParam,
            list_users::ListUsersLdapFilterParam, update_group::UpdateGroupParams,
            update_user::UpdateUserParams,
        },
        types::{
            group::{LuaGroup, LuaGroupDetails},
            result::MyLuaResult,
            schema::LuaSchema,
            user::{LuaUser, LuaUserAndGroupsVec},
        },
    },
};

pub struct LuaBackendAPI<A>
where
    A: BackendAPI + 'static,
{
    pub underlying: &'static A,
    pub lua: &'static Lua,
}

impl<A: BackendAPI + 'static> UserData for LuaBackendAPI<A> {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        //
        // User Listing
        //
        methods.add_async_method("list_users", |_, ctx, args: Table| {
            let params = ListUsersLdapFilterParam::from(&args);
            let api: &'static A = ctx.underlying;
            async {
                match params {
                    Ok(p) => {
                        match api
                            .list_users_ldap_filter(p.ldap_filter, p.get_groups)
                            .await
                        {
                            Ok(users_and_groups) => {
                                let res: LuaUserAndGroupsVec = users_and_groups.into();
                                Ok(MyLuaResult(Ok(res.user_and_groups)))
                            }
                            Err(e) => Ok(MyLuaResult(Err(e))),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        });
        //
        // Group Listing
        //
        methods.add_async_method("list_groups", |_, ctx, args: Table| {
            let params = ListGroupsLdapFilterParam::from(&args);
            let api: &'static A = ctx.underlying;
            async {
                match params {
                    Ok(p) => match api.list_groups_ldap_filter(p.ldap_filter).await {
                        Ok(groups) => Ok(MyLuaResult(Ok(groups
                            .into_iter()
                            .map(LuaGroup::from)
                            .collect::<Vec<_>>()))),
                        Err(e) => Ok(MyLuaResult(Err(e))),
                    },
                    Err(e) => Err(e),
                }
            }
        });
        //
        // Read Schema
        //
        methods.add_async_method("get_schema", |_, ctx, ()| {
            let api: &'static A = ctx.underlying;
            let lua: &'static Lua = ctx.lua;
            async {
                match api.get_schema().await {
                    Ok(s) => {
                        let schema: LuaSchema = s.into();
                        Ok(MyLuaResult(
                            lua.to_value(&schema).map_err(|e| e.to_string()),
                        ))
                    }
                    Err(e) => Ok(MyLuaResult(Err(e))),
                }
            }
        });
        //
        // Schema
        //
        methods.add_async_method("add_user_attribute", |_, ctx, args: Table| {
            let params = CreateAttributeParams::from(&args);
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.add_user_attribute(params?.into()).await)) }
        });
        methods.add_async_method("add_group_attribute", |_, ctx, args: Table| {
            let params = CreateAttributeParams::from(&args);
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.add_group_attribute(params?.into()).await)) }
        });
        methods.add_async_method("delete_user_attribute", |_, ctx, name: String| {
            let attr = AttributeName::from(&name);
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.delete_user_attribute(attr).await)) }
        });
        methods.add_async_method("delete_group_attribute", |_, ctx, name: String| {
            let attr = AttributeName::from(&name);
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.delete_group_attribute(attr).await)) }
        });
        methods.add_async_method("add_user_object_class", |_, ctx, name: String| {
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.add_user_object_class(name.into()).await)) }
        });
        methods.add_async_method("delete_user_object_class", |_, ctx, name: String| {
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.delete_user_object_class(name.into()).await)) }
        });
        methods.add_async_method("add_group_object_class", |_, ctx, name: String| {
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.add_group_object_class(name.into()).await)) }
        });
        methods.add_async_method("delete_group_object_class", |_, ctx, n: String| {
            let api: &'static A = ctx.underlying;
            async { Ok(MyLuaResult(api.delete_group_object_class(n.into()).await)) }
        });
        //
        // Groups
        //
        methods.add_async_method("get_group_details", |_, ctx, group_id: i32| {
            let api: &'static A = ctx.underlying;
            async move {
                match api.get_group_details(GroupId(group_id)).await {
                    Ok(group) => {
                        let group_details: LuaGroupDetails = group.into();
                        Ok(MyLuaResult(Ok(group_details)))
                    }
                    Err(e) => Ok(MyLuaResult(Err(e))),
                }
            }
        });
        methods.add_async_method("update_group", |_, ctx, args: Table| {
            let params = UpdateGroupParams::from(&args);
            let api: &'static A = ctx.underlying;
            async {
                match params {
                    Ok(p) => match api.update_group(p.into()).await {
                        Ok(()) => Ok(MyLuaResult(Ok(()))),
                        Err(e) => Ok(MyLuaResult(Err(e))),
                    },
                    Err(e) => Err(e),
                }
            }
        });
        methods.add_async_method("create_group", |_, ctx, args: Table| {
            let params = CreateGroupParams::from(&args);
            let api: &'static A = ctx.underlying;
            async move {
                match params {
                    Ok(p) => match api.create_group(p.into()).await {
                        Ok(group_id) => Ok(MyLuaResult(Ok(group_id.0))),
                        Err(e) => Ok(MyLuaResult(Err(e))),
                    },
                    Err(e) => Err(e),
                }
            }
        });
        methods.add_async_method("delete_group", |_, ctx, group_id: i32| {
            let api: &'static A = ctx.underlying;
            async move {
                match api.delete_group(GroupId(group_id)).await {
                    Ok(()) => Ok(MyLuaResult(Ok(()))),
                    Err(e) => Ok(MyLuaResult(Err(e))),
                }
            }
        });
        //
        // Users
        //
        methods.add_async_method("get_user_details", |_, ctx, user_id: String| {
            let api: &'static A = ctx.underlying;
            async {
                match api.get_user_details(&UserId::from(user_id)).await {
                    Ok(user) => {
                        let u: LuaUser = user.into();
                        Ok(MyLuaResult(Ok(u)))
                    }
                    Err(e) => Ok(MyLuaResult(Err(e))),
                }
            }
        });
        methods.add_async_method("create_user", |_, ctx, args: Table| {
            let params = CreateUserParams::from(&args);
            let api: &'static A = ctx.underlying;
            async move {
                match params {
                    Ok(p) => match api.create_user(p.into()).await {
                        Ok(()) => Ok(MyLuaResult(Ok(()))),
                        Err(e) => Ok(MyLuaResult(Err(e))),
                    },
                    Err(e) => Err(e),
                }
            }
        });
        methods.add_async_method("update_user", |_, ctx, args: Table| {
            let params = UpdateUserParams::from(&args);
            let api: &'static A = ctx.underlying;
            async move {
                match params {
                    Ok(p) => match api.update_user(p.into()).await {
                        Ok(()) => Ok(MyLuaResult(Ok(()))),
                        Err(e) => Ok(MyLuaResult(Err(e))),
                    },
                    Err(e) => Err(e),
                }
            }
        });
        methods.add_async_method("delete_user", |_, ctx, user_id: String| {
            let api: &'static A = ctx.underlying;
            async {
                match api.delete_user(&UserId::from(user_id)).await {
                    Ok(()) => Ok(MyLuaResult(Ok(()))),
                    Err(e) => Ok(MyLuaResult(Err(e))),
                }
            }
        });
        methods.add_async_method(
            "add_user_to_group",
            |_, ctx, (user_id, group_id): (String, i32)| {
                let api: &'static A = ctx.underlying;
                async move {
                    match api
                        .add_user_to_group(&UserId::from(user_id), GroupId(group_id))
                        .await
                    {
                        Ok(()) => Ok(MyLuaResult(Ok(()))),
                        Err(e) => Ok(MyLuaResult(Err(e))),
                    }
                }
            },
        );
        methods.add_async_method(
            "remove_user_from_group",
            |_, ctx, (user_id, group_id): (String, i32)| {
                let api: &'static A = ctx.underlying;
                async move {
                    match api
                        .remove_user_from_group(&UserId::from(user_id), GroupId(group_id))
                        .await
                    {
                        Ok(()) => Ok(MyLuaResult(Ok(()))),
                        Err(e) => Ok(MyLuaResult(Err(e))),
                    }
                }
            },
        );
        methods.add_async_method("get_user_groups", |_, ctx, user_id: String| {
            let api: &'static A = ctx.underlying;
            async {
                match api.get_user_groups(&UserId::from(user_id)).await {
                    Ok(groups) => {
                        let g: Vec<LuaGroupDetails> =
                            groups.into_iter().map(GroupDetails::into).collect();
                        Ok(MyLuaResult(Ok(g)))
                    }
                    Err(e) => Ok(MyLuaResult(Err(e))),
                }
            }
        });
    }
}
