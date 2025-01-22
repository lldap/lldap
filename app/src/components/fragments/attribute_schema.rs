use crate::infra::attributes::AttributeDescription;
use lldap_validation::attributes::{validate_attribute_name, ALLOWED_CHARACTERS_DESCRIPTION};
use yew::{html, Html};

fn render_attribute_aliases(attribute_description: &AttributeDescription) -> Html {
    if attribute_description.aliases.is_empty() {
        html! {}
    } else {
        html! {
          <>
            <br/>
            <small class="text-muted">
              {"Aliases: "}
              {attribute_description.aliases.join(", ")}
            </small>
          </>
        }
    }
}

fn render_attribute_validation_warnings(attribute_name: &str) -> Html {
    match validate_attribute_name(attribute_name) {
        Ok(()) => {
            html! {}
        }
        Err(_invalid_chars) => {
            html! {
              <>
                <br/>
                <small class="text-warning">
                  {"Warning: This attribute uses one or more invalid characters "}
                  {"("}{ALLOWED_CHARACTERS_DESCRIPTION}{"). "}
                  {"Some clients may not support it."}
                </small>
              </>
            }
        }
    }
}

pub fn render_attribute_name(
    hardcoded: bool,
    attribute_description: &AttributeDescription,
) -> Html {
    html! {
      <>
        {&attribute_description.attribute_name}
        {if hardcoded {render_attribute_aliases(attribute_description)} else {html!{}}}
        {render_attribute_validation_warnings(attribute_description.attribute_name)}
      </>
    }
}
