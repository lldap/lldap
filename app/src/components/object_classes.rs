use crate::components::{
    add_group_object_class::ListGroupObjectClass, add_user_object_class::ListUserObjectClass,
};
use yew::prelude::*;

#[function_component(ObjectClasses)]
pub fn object_classes() -> Html {
    html! {
        <div class="row g-4">
            <section class="col-12 col-lg-6">
                <h2>{"User object classes"}</h2>
                <ListUserObjectClass />
            </section>
            <section class="col-12 col-lg-6">
                <h2>{"Group object classes"}</h2>
                <ListGroupObjectClass />
            </section>
        </div>
    }
}
