use yew::{Children, Properties, function_component, html, virtual_dom::AttrValue};

#[derive(Properties, PartialEq)]
pub struct Props {
    pub label: AttrValue,
    pub id: AttrValue,
    pub children: Children,
}

#[function_component(StaticValue)]
pub fn static_value(props: &Props) -> Html {
    html! {
      <div class="row mb-3">
        <label for={props.id.clone()}
          class="form-label col-4 col-form-label">
          {&props.label}
          {":"}
        </label>
        <div class="col-8">
          <span id={props.id.clone()} class="form-control-static">
            {for props.children.iter()}
          </span>
        </div>
      </div>
    }
}
