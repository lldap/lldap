-- Plugin for PAM attributes
--
-- Configuration:
--   uid_offset: offset applied to all assigned uid's (default: 100000)
--   gid_offset: offset applied to all assigned gid's (default: 100000)
--   default_group: name of default group for users gid attribute (default: pam_users)
--
-- Creates the following:
--   User Attributes: uidnumber, gidnumber
--   Group Attributes: gidnumber
--   Groups: pam_users (default)
--
-- Strives to maintain:
--   Users: all have a unique uidnumber
--   Users: all users by default have a gidnumber corresponding to the
--          pam_users group created.
--   Groups: all groups have a unique uidnumber
--
-- Group will only be created when a user needs the gidnumber for
-- it, this is done to avoid it being created as group 1, before
-- lldap_admin, in new setups.
--
-- TODO:
--   3. max uid should be stored in a key-value store instead
--

-- keys used for this plugins key-value store
local KVKEYS = {
    NEXT_UID = "next-uid"
}

local get_config_gid_offset = function(context)
    if context.configuration.gid_offset ~= nil then
        return tonumber(context.configuration.gid_offset)
    else
        -- return default
        return 100000
    end
end


local get_config_uid_offset = function(context)
    if context.configuration.uid_offset ~= nil then
        return tonumber(context.configuration.uid_offset)
    else
        -- return default
        return 100000
    end
end

local get_config_default_group = function(context)
    if context.configuration.default_group ~= nil then
        return context.configuration.default_group
    else
        -- return default
        return "pam_users"
    end
end

local resolve_gid_default_group = function(context)
    local group_name = get_config_default_group(context)
    local groups = context.api:list_groups({ filter = "(cn=" .. group_name .. ")" })
    local group_id = nil
    if lldap.tables:empty(groups) then
        lldap.log:debug("Creating group:" .. group_name)
        local id, err = context.api:create_group({
            display_name = group_name,
            attributes = {}
        })
        if err ~= nil then
            -- Error
            error("Failed to create group: " .. group_name, 1)
        end
        lldap.log:debug("Created '" .. group_name .. "' group with id " .. tostring(id))
        local group_gidnumber = get_config_gid_offset(context) + id
        local res, err = context.api:update_group({
            group_id = id,
            insert_attributes = {
                gidnumber = { int = group_gidnumber }
            }
        })
        if err ~= nil then
            error("Failed to set gidnumber attribute to '" .. group_name .. "' group", 1)
        end
        lldap.log:debug("Assigned gidnumber to '" .. group_name .. "': " .. tostring(group_gidnumber))
        group_id = group_gidnumber
    else
        group_id = groups[1].attributes.gidnumber.int
    end
    return group_id
end

local resolve_next_uid = function(context, uid_offset)
    local nextuid, err = context.kvstore:fetch_and_increment(KVKEYS.NEXT_UID, uid_offset)
    if err ~= nil then
        error("Unable to resolve next-uid from plugin KV store. Error: " .. tostring(err), 1)
    end
    return nextuid
end

local assign_user_attributes = function(context)
    -- Ensure that the uidNumber for the created user is unique.
    lldap.log:debug("Resolving current maximum uid and gid")
    local uid_offset = get_config_uid_offset(context)
    -- obtain list of all users in the system
    local users, err = context.api:list_users({})
    if err ~= nil then
        -- Error
        error("Failed to list_users: " .. tostring(err), 1)
    end
    if not lldap.tables:empty(users) then
        -- obtain id of shared pam group
        local group_id = resolve_gid_default_group(context)
        lldap.log:debug("Resolved default group to ID: " .. tostring(group_id))
        -- assign uid/gid to any users missing
        for idx, user_and_group in pairs(users) do
            if user_and_group.user.attributes.uidnumber == nil then
                local nextuid = resolve_next_uid(context, uid_offset)
                -- assign the uid to user
                local res, err = context.api:update_user({
                    user_id = user_and_group.user.user_id,
                    insert_attributes = {
                        uidnumber = { int = nextuid },
                    }
                })
                if err ~= nil then
                    lldap.log:warn("Failed to set uidnumber for user_id: " .. user_and_group.user.user_id)
                end
            end
            if user_and_group.user.attributes.gidnumber == nil then
                -- assign the gid to user
                local res, err = context.api:update_user({
                    user_id = user_and_group.user.user_id,
                    insert_attributes = {
                        gidnumber = { int = group_id }
                    }
                })
                if err ~= nil then
                    lldap.log:warn("Failed to set gidnumber for user_id: " .. user_and_group.user.user_id)
                end
            end
        end
    end
end

local assign_group_attributes = function(context)
    local groups, err = context.api:list_groups({})
    if err ~= nil then
        lldap.log:warn("Unable to search groups")
    else
        for idx, group in pairs(groups) do
            lldap.log:debug("Group: " .. group.display_name)
            if group.attributes.gidnumber == nil then
                local res, err = context.api:update_group({
                    group_id = group.group_id,
                    insert_attributes = {
                        gidnumber = {
                            int = get_config_gid_offset(context) + group.group_id
                        }
                    }
                })
                if err ~= nil then
                    lldap.log:warn("Failed to set gidnumber for group: " .. group.display_name)
                end
            end
        end
    end
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
    local schema = context.api:get_schema()
    -- ensure we have the basic samba related attributes for users
    lldap.log:debug("Creating user attributes")
    ensure_user_attribute_exists(context, schema, "uidnumber", "Integer")
    ensure_user_attribute_exists(context, schema, "gidnumber", "Integer")
    -- ensure we have the basic samba related attributes for groups
    lldap.log:debug("Creating group attributes")
    ensure_group_attribute_exists(context, schema, "gidnumber", "Integer")
    -- assign uidnumber and gidnumber to all users missing it
    assign_user_attributes(context)
    -- assign gidnumber to all groups missing it
    assign_group_attributes(context)
end

local on_create_user = function(context, args)
    -- User being created, assign a uid and gid to it.
    if args.attributes.uidnumber == nil then
        local nextuid = resolve_next_uid(context, get_config_gid_offset(context))
        -- assign the uid to user
        args.attributes.uidnumber = { int = nextuid }
    else
        if args.attributes.uidnumber.int ~= nil then
            local current_uid = args.attributes.uidnumber.int
            -- already have a uid assigned, let's ensure
            -- it's not higher than our currently stored next_uid
            local nextuid, err = context.kvstore:fetch_int(KVKEYS.NEXT_UID)
            if ((nextuid ~= nil) and (nextuid <= current_uid)) then
                -- increase our stored nextuid
                local res, err = context.kvstore:store_int(KVKEYS.NEXT_UID, current_uid + 1)
                if res ~= nil then
                    error("Unable to increase local next-uid counter. Aborting. Error: " .. tostring(err), 1)
                end
            end
        end
    end
    if args.attributes.gidnumber == nil then
        local group_id = resolve_gid_default_group(context)
        args.attributes.gidnumber = { int = group_id }
    end
    -- The returned args will replace the original args.
    return args
end

local on_created_group = function(context, args)
    -- assign gidnumber to all groups missing it
    -- we do this after creation, as we'd like to just use the
    -- assigned group_id for the gid, plus the gid_offset.
    assign_group_attributes(context)
    return args
end

return {
    name = "pam",
    version = "1.0",
    author = "broeng",
    repo = "https://github.com/broeng/lldap-plugins/blob/main/pam/pam.lua",
    init = initialize_attributes,
    listeners = {
        { event = "on_create_user",   priority = 50, impl = on_create_user },
        { event = "on_created_group", priority = 50, impl = on_created_group },
    },
}
