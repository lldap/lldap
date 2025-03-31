use anyhow::{Result, anyhow, ensure};
use validator::validate_email;
use web_sys::{FormData, HtmlFormElement};
use yew::NodeRef;

#[derive(Debug)]
pub struct AttributeValue {
    pub name: String,
    pub values: Vec<String>,
}

pub struct GraphQlAttributeSchema {
    pub name: String,
    pub is_list: bool,
    pub is_readonly: bool,
    pub is_editable: bool,
}

fn validate_attributes(
    all_values: &[AttributeValue],
    email_is_required: EmailIsRequired,
) -> Result<()> {
    let maybe_email_values = all_values.iter().find(|a| a.name == "mail");
    if email_is_required.0 || maybe_email_values.is_some() {
        let email_values = &maybe_email_values
            .ok_or_else(|| anyhow!("Email is required"))?
            .values;
        ensure!(email_values.len() == 1, "Email is required");
        ensure!(validate_email(&email_values[0]), "Email is not valid");
    }
    Ok(())
}

pub struct IsAdmin(pub bool);
pub struct EmailIsRequired(pub bool);

pub fn read_all_form_attributes(
    schema: impl IntoIterator<Item = impl Into<GraphQlAttributeSchema>>,
    form_ref: &NodeRef,
    is_admin: IsAdmin,
    email_is_required: EmailIsRequired,
) -> Result<Vec<AttributeValue>> {
    let form = form_ref.cast::<HtmlFormElement>().unwrap();
    let form_data = FormData::new_with_form(&form)
        .map_err(|e| anyhow!("Failed to get FormData: {:#?}", e.as_string()))?;
    let all_values = schema
        .into_iter()
        .map(Into::<GraphQlAttributeSchema>::into)
        .filter(|attr| !attr.is_readonly && (is_admin.0 || attr.is_editable))
        .map(|attr| -> Result<AttributeValue> {
            let val = form_data
                .get_all(attr.name.as_str())
                .iter()
                .map(|js_val| js_val.as_string().unwrap_or_default())
                .filter(|val| !val.is_empty())
                .collect::<Vec<String>>();
            ensure!(
                val.len() <= 1 || attr.is_list,
                "Multiple values supplied for non-list attribute {}",
                attr.name
            );
            Ok(AttributeValue {
                name: attr.name.clone(),
                values: val,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    validate_attributes(&all_values, email_is_required)?;
    Ok(all_values)
}
