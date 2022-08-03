use crate::{
    components::user_details::User,
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Error, Result};
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;

/// The fields of the form, with the editable details and the constraints.
#[derive(Model, Validate, PartialEq, Clone)]
pub struct UserModel {
    #[validate(email)]
    email: String,
    #[validate(length(min = 1, message = "Display name is required"))]
    display_name: String,
    first_name: String,
    last_name: String,
}

/// The GraphQL query sent to the server to update the user details.
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/update_user.graphql",
    response_derives = "Debug",
    variables_derives = "Clone,PartialEq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdateUser;

/// A [yew::Component] to display the user details, with a form allowing to edit them.
pub struct UserDetailsForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<UserModel>,
    /// True if we just successfully updated the user, to display a success message.
    just_updated: bool,
}

pub enum Msg {
    /// A form field changed.
    Update,
    /// The "Submit" button was clicked.
    SubmitClicked,
    /// We got the response from the server about our update message.
    UserUpdated(Result<update_user::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    /// The current user details.
    pub user: User,
    /// Callback to report errors (e.g. server error).
    pub on_error: Callback<Error>,
}

impl CommonComponent<UserDetailsForm> for UserDetailsForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitClicked => self.submit_user_update_form(),
            Msg::UserUpdated(response) => self.user_update_finished(response),
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for UserDetailsForm {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let model = UserModel {
            email: props.user.email.clone(),
            display_name: props.user.display_name.clone(),
            first_name: props.user.first_name.clone(),
            last_name: props.user.last_name.clone(),
        };
        Self {
            common: CommonComponentParts::<Self>::create(props, link),
            form: yew_form::Form::new(model),
            just_updated: false,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.just_updated = false;
        CommonComponentParts::<Self>::update_and_report_error(
            self,
            msg,
            self.common.on_error.clone(),
        )
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        type Field = yew_form::Field<UserModel>;
        html! {
          <div class="py-3">
            <form class="form">
              <div class="form-group row mb-3">
                <label for="userId"
                  class="form-label col-4 col-form-label">
                  {"User ID: "}
                </label>
                <div class="col-8">
                  <span id="userId" class="form-constrol-static">{&self.common.user.id}</span>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="email"
                  class="form-label col-4 col-form-label">
                  {"Email*: "}
                </label>
                <div class="col-8">
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form=&self.form
                    field_name="email"
                    autocomplete="email"
                    oninput=self.common.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("email")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="display_name"
                  class="form-label col-4 col-form-label">
                  {"Display Name*: "}
                </label>
                <div class="col-8">
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form=&self.form
                    field_name="display_name"
                    autocomplete="name"
                    oninput=self.common.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("display_name")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="first_name"
                  class="form-label col-4 col-form-label">
                  {"First Name: "}
                </label>
                <div class="col-8">
                  <Field
                    class="form-control"
                    form=&self.form
                    field_name="first_name"
                    autocomplete="given-name"
                    oninput=self.common.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("first_name")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="last_name"
                  class="form-label col-4 col-form-label">
                  {"Last Name: "}
                </label>
                <div class="col-8">
                  <Field
                    class="form-control"
                    form=&self.form
                    field_name="last_name"
                    autocomplete="family-name"
                    oninput=self.common.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("last_name")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="creationDate"
                class="form-label col-4 col-form-label">
                {"Creation date: "}
                </label>
                <div class="col-8">
                  <span id="creationDate" class="form-constrol-static">{&self.common.user.creation_date.date().naive_local()}</span>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="uuid"
                class="form-label col-4 col-form-label">
                {"UUID: "}
                </label>
                <div class="col-8">
                  <span id="creationDate" class="form-constrol-static">{&self.common.user.uuid}</span>
                </div>
              </div>
              <div class="form-group row justify-content-center">
                <button
                  type="submit"
                  class="btn btn-primary col-auto col-form-label"
                  disabled=self.common.is_task_running()
                  onclick=self.common.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})>
                  {"Update"}
                </button>
              </div>
            </form>
            <div hidden=!self.just_updated>
              <span>{"User successfully updated!"}</span>
            </div>
          </div>
        }
    }
}

impl UserDetailsForm {
    fn submit_user_update_form(&mut self) -> Result<bool> {
        if !self.form.validate() {
            bail!("Invalid inputs");
        }
        let base_user = &self.common.user;
        let mut user_input = update_user::UpdateUserInput {
            id: self.common.user.id.clone(),
            email: None,
            displayName: None,
            firstName: None,
            lastName: None,
            avatar: None,
        };
        let default_user_input = user_input.clone();
        let model = self.form.model();
        let email = model.email;
        if base_user.email != email {
            user_input.email = Some(email);
        }
        if base_user.display_name != model.display_name {
            user_input.displayName = Some(model.display_name);
        }
        if base_user.first_name != model.first_name {
            user_input.firstName = Some(model.first_name);
        }
        if base_user.last_name != model.last_name {
            user_input.lastName = Some(model.last_name);
        }
        // Nothing changed.
        if user_input == default_user_input {
            return Ok(false);
        }
        let req = update_user::Variables { user: user_input };
        self.common.call_graphql::<UpdateUser, _>(
            req,
            Msg::UserUpdated,
            "Error trying to update user",
        );
        Ok(false)
    }

    fn user_update_finished(&mut self, r: Result<update_user::ResponseData>) -> Result<bool> {
        self.common.cancel_task();
        match r {
            Err(e) => return Err(e),
            Ok(_) => {
                let model = self.form.model();
                self.common.user = User {
                    id: self.common.user.id.clone(),
                    email: model.email,
                    display_name: model.display_name,
                    first_name: model.first_name,
                    last_name: model.last_name,
                    creation_date: self.common.user.creation_date,
                    uuid: self.common.user.uuid.clone(),
                    groups: self.common.user.groups.clone(),
                };
                self.just_updated = true;
            }
        };
        Ok(true)
    }
}
