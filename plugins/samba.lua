if lldap == nil then
    lldap = {}
end

local ensure_user_attribute_exists = function(context, schema, attribute_name, attribute_type)
    if schema.user_attributes.attributes[attribute_name] == nil then
        local res = context.api:add_user_attribute({
            name = attribute_name,
            attribute_type = attribute_type,
            is_list = false,
            is_visible = true,
            is_editable = false,
        })
        if res ~= nil then
            -- Error.
            error("Got error from creating '" .. attribute_name .. "' attribute", 1)
        end
    end
end

local ensure_group_attribute_exists = function(context, schema, attribute_name, attribute_type)
    if schema.group_attributes.attributes[attribute_name] == nil then
        local res = context.api:add_group_attribute({
            name = attribute_name,
            attribute_type = attribute_type,
            is_list = false,
            is_visible = true,
            is_editable = false,
        })
        if res ~= nil then
            -- Error.
            error("Got error from creating '" .. attribute_name .. "' group attribute", 1)
        end
    end
end

local initialize_attributes = function(context)
    lldap.log:debug("Initializing samba.lua")
    local schema = context.api:get_schema()
    -- ensure we have the basic samba related attributes for users
    ensure_user_attribute_exists(context, schema, "sambantpassword", "String")
    ensure_user_attribute_exists(context, schema, "sambasid", "String")
    ensure_user_attribute_exists(context, schema, "sambaacctflags", "String")
    -- ensure we have the basic samba related attributes for groups
    ensure_group_attribute_exists(context, schema, "sambasid", "String")
    -- ensure we have the 'sambaSamAccount' user object class
    if schema.extra_user_object_classes.sambaSamAccount == nil then
        local res = context.api:add_user_object_class("sambaSamAccount")
        if res ~= nil then
            -- Error.
            lldap.log:warn("Got error from creating 'sambaSamAccount' user object class")
            return res
        end
    end
end

local on_password_update = function(context, args)
    lldap.log:debug("New password being set for " .. args.user_id)
    utf16_bytes = lldap.strings:to_utf16le(args.password)
    hashed = lldap.hashing:md4_hash_bytes(utf16bytes)
    encoded = lldap.encoding:base16_encode(md4hash)
    ntlm_hash = encoded:upper()
    lldap.log:debug("New samba hash: " .. ntlm_hash)
    context.api:update_user({
        user_id = args.user_id,
        email = nil,
        display_name = nil,
        delete_attributes = {},
        insert_attributes = {
            sambantpassword = { string = ntlm_hash }
        }
    })
    return args
end

local inject_metadata_attributes = function(users_and_groups)
    for k, v in pairs(users_and_groups.users) do
        v.user.attributes.shadowmin = { int = 1000 }
        v.user.attributes.shadowmax = { int = 999999 }
    end
end

local on_search_result = function(context, args)
    local search_request = args.search_request
    print("search filter: " .. tostring(search_request.filter))
    if search_request.filter ~= nil then
        local expected_filter = { equality = { "objectClass", "sambaDomain" } }
        if lldap.tables:eq(search_request.filter, expected_filter) then
            args.search_result.ldap = {
                {
                    search_result_entry = {
                        dn = "dc=example,dc=com",
                        attributes = {
                            {
                                atype = "sambaDomainName",
                                vals = {
                                    lldap.strings:to_utf8("example")
                                }
                            }
                        }
                    }
                }
            }
        end
        if lldap.tables:has_subtree(search_request.filter, expected_filter) then
            print("HAS SUBTREE")
        end
    end
    -- inject some samba related attributes that we don't really want in our schema.
    if args.search_result.users_and_groups ~= nil then
        inject_metadata_attributes(args.search_result.users_and_groups)
    end
    return args
end

return {
    api_version = 1,
    name = "samba",
    version = "1.0",
    author = "broeng",
    repo = "https://github.com/nitnelave/lldap_plugin_poc/lua/pam.lua",
    init = initialize_attributes,
    listeners = {
        -- Which event you subscribe to, the priority (highest gets called first), and the function to call.
        --{ event = "on_create_user",         priority = 40, impl = on_create_user },
        --{ event = "on_create_group",        priority = 40, impl = on_create_group },
        { event = "on_ldap_password_update", priority = 40, impl = on_password_update },
        { event = "on_ldap_search_result",   priority = 40, impl = on_search_result },
    },
}
