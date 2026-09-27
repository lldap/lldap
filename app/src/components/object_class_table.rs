use yew::prelude::*;

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectClass {
    pub name: String,
    pub is_hardcoded: bool,
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub object_classes: Option<Vec<ObjectClass>>,
    pub delete_disabled: bool,
    pub on_delete: Callback<String>,
}

#[function_component(ObjectClassTable)]
pub fn object_class_table(props: &Props) -> Html {
    let Some(object_classes) = &props.object_classes else {
        return html! {"Loading..."};
    };

    let (hardcoded, custom): (Vec<_>, Vec<_>) =
        object_classes.iter().partition(|class| class.is_hardcoded);
    html! {
        <>
            {view_table(&hardcoded, true, props)}
            {view_table(&custom, false, props)}
        </>
    }
}

fn view_table(object_classes: &[&ObjectClass], hardcoded: bool, props: &Props) -> Html {
    html! {
        <div class="table-responsive">
            <h3>{if hardcoded {"Hardcoded"} else {"User-defined"}}{" object classes"}</h3>
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>{"Object class"}</th>
                        {if hardcoded {html! {}} else {html! {<th>{"Delete"}</th>}}}
                    </tr>
                </thead>
                <tbody>
                    {object_classes.iter().map(|object_class| {
                        let name = object_class.name.clone();
                        let on_delete = props.on_delete.clone();
                        html! {
                            <tr key={name.clone()}>
                                <td>{&name}</td>
                                {if hardcoded {
                                    html! {}
                                } else {
                                    html! {
                                        <td>
                                            <button
                                                class="btn btn-danger"
                                                disabled={props.delete_disabled}
                                                onclick={Callback::from(move |_| on_delete.emit(name.clone()))}>
                                                <i class="bi-x-circle-fill" aria-label="Delete object class" />
                                            </button>
                                        </td>
                                    }
                                }}
                            </tr>
                        }
                    }).collect::<Html>()}
                </tbody>
            </table>
        </div>
    }
}
