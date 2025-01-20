use yew::{html, Html};

use crate::infra::attributes::AttributeDescription;

pub fn render_attribute_name(
    hardcoded: bool,
    attribute_identifier: &String,
    attribute_description: &AttributeDescription,
) -> Html {
    if hardcoded {
        html! {
          <>
            {&attribute_description.attribute_name}
            {
              if attribute_description.aliases.is_empty() {
                html!{}
              } else {
                html!{
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
          </>
        }
    } else {
        html! {
          {&attribute_identifier}
        }
    }
}
