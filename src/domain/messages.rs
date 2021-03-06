
struct LdapMessage {
    message_id: u32,
    operation: LdapOperation,
}

enum LdapOperation {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    //UnbindRequest(UnbindRequest),
}

struct BindRequest {
    version: u8,
    name: String,
    authentication: AuthenticationChoice,
}

enum AuthenticationChoice {
    Simple(String),
    // Sasl
}

struct BindResponse {
    result_code: u8,
    matched_dn: String,
    diagnostic_message: String,
}
