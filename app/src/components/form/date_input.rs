use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};
use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;
use yew::{Event, Properties, function_component, html, use_state, virtual_dom::AttrValue};

#[derive(Properties, PartialEq)]
pub struct DateTimeInputProps {
    pub name: AttrValue,
    pub value: Option<String>,
    #[prop_or(None)]
    pub onchange: Option<yew::Callback<String>>,
}

#[function_component(DateTimeInput)]
pub fn date_time_input(props: &DateTimeInputProps) -> Html {
    let value = use_state(|| {
        props
            .value
            .as_ref()
            .and_then(|x| DateTime::<Utc>::from_str(x).ok())
    });

    let onchange_callback = props.onchange.clone();

    html! {
        <div class="input-group">
            <input
                type="hidden"
                name={props.name.clone()}
                value={value.as_ref().map(|v: &DateTime<Utc>| v.to_rfc3339())} />
            <input
                type="datetime-local"
                step="1"
                class="form-control"
                value={value.as_ref().map(|v: &DateTime<Utc>| v.naive_utc().to_string())}
                onchange={move |e: Event| {
                    let string_val =
                        e.target()
                         .expect("Event should have target")
                         .unchecked_into::<HtmlInputElement>()
                         .value();
                    let new_value = NaiveDateTime::from_str(&string_val)
                        .ok()
                        .map(|x| DateTime::from_naive_utc_and_offset(x, Utc));
                    value.set(new_value.clone());

                    if let Some(callback) = &onchange_callback {
                        if let Some(dt) = new_value {
                            callback.emit(dt.to_rfc3339());
                        } else {
                            callback.emit(String::new());
                        }
                    }
                }} />
            <span class="input-group-text">{"UTC"}</span>
        </div>
    }
}
