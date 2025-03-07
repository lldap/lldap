pub const SCRIPT_TEST_LIB: &'static str = r#"
    local assert_eq = function(a, b)
        if type(a) ~= type(b) then
            error(type(a) .. " is not a type " .. type(b))
        end
        if type(a) == "table" then
            if not lldap.tables:eq(a, b) then
                error("table a not equal to table b")
            end
        else
            if a ~= b then
                error(tostring(a) .. " != " .. tostring(b), 1)
            end
        end
    end
"#;

pub fn make_init_script(init_body: &str) -> String {
    format!(
        r#"
        {SCRIPT_TEST_LIB}

        local init = function(context)
            {init_body}
        end
        return {{
            api_version = 1,
            name = "test",
            version = "1.0",
            author = "broeng",
            init = init,
            listeners = {{}},
        }}
    "#
    )
}
