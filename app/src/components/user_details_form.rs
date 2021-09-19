use crate::{components::user_details::User, infra::api::HostService};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};
use yew_form_derive::Model;

lazy_static::lazy_static! {
    static ref EMAIL_RE: regex::Regex = regex::Regex::new("^[^@]+@[^@]+\\.[^@]+$").unwrap();
}

/// The fields of the form, with the editable details and the constraints.
#[derive(Model, Validate, PartialEq, Clone)]
pub struct UserModel {
    #[validate(regex(path = "EMAIL_RE", message = "Enter a valid email"))]
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
    link: ComponentLink<Self>,
    props: Props,
    form: yew_form::Form<UserModel>,
    /// True if we just successfully updated the user, to display a success message.
    just_updated: bool,
    _task: Option<FetchTask>,
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
            link,
            form: yew_form::Form::new(model),
            props,
            just_updated: false,
            _task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.just_updated = false;
        match self.handle_msg(msg) {
            Err(e) => {
                ConsoleService::error(&e.to_string());
                self.props.on_error.emit(e);
                true
            }
            Ok(b) => b,
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        type Field = yew_form::Field<UserModel>;
        html! {
          <>
          <form>
            <div class="form-group">
              <span>{"User ID: "}</span>
                <span>{&self.props.user.id}</span>
            </div>
            <div class="form-group">
              <label for="email">{"Email: "}</label>
              <Field form=&self.form field_name="email" oninput=self.link.callback(|_| Msg::Update) />
              <div class="invalid-feedback">
                {&self.form.field_message("email")}
              </div>
            </div>
            <div class="form-group">
              <label for="display_name">{"Display Name: "}</label>
              <Field form=&self.form field_name="display_name" oninput=self.link.callback(|_| Msg::Update) />
              <div class="invalid-feedback">
                {&self.form.field_message("display_name")}
              </div>
            </div>
            <div class="form-group">
              <label for="first_name">{"First Name: "}</label>
              <Field form=&self.form field_name="first_name" oninput=self.link.callback(|_| Msg::Update) />
              <div class="invalid-feedback">
                {&self.form.field_message("first_name")}
              </div>
            </div>
            <div class="form-group">
              <label for="last_name">{"Last Name: "}</label>
              <Field form=&self.form field_name="last_name" oninput=self.link.callback(|_| Msg::Update) />
              <div class="invalid-feedback">
                {&self.form.field_message("last_name")}
              </div>
            </div>
            <div class="form-group">
              <span>{"Creation date: "}</span>
              <span>{&self.props.user.creation_date.with_timezone(&chrono::Local)}</span>
            </div>
            <div class="form-group">
              <button type="button" onclick=self.link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})>{"Update"}</button>
            </div>
          </form>
          <div hidden=!self.just_updated>
            <span>{"User successfully updated!"}</span>
          </div>
          </>
        }
    }
}

impl UserDetailsForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitClicked => self.submit_user_update_form(),
            Msg::UserUpdated(response) => self.user_update_finished(response),
        }
    }

    fn submit_user_update_form(&mut self) -> Result<bool> {
        let base_user = &self.props.user;
        let mut user_input = update_user::UpdateUserInput {
            id: self.props.user.id.clone(),
            email: None,
            displayName: None,
            firstName: None,
            lastName: None,
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
        self._task = Some(HostService::graphql_query::<UpdateUser>(
            req,
            self.link.callback(Msg::UserUpdated),
            "Error trying to update user",
        )?);
        Ok(false)
    }

    fn user_update_finished(&mut self, r: Result<update_user::ResponseData>) -> Result<bool> {
        match r {
            Err(e) => return Err(e),
            Ok(_) => {
                let model = self.form.model();
                self.props.user = User {
                    id: self.props.user.id.clone(),
                    email: model.email,
                    display_name: model.display_name,
                    first_name: model.first_name,
                    last_name: model.last_name,
                    creation_date: self.props.user.creation_date,
                    groups: self.props.user.groups.clone(),
                };
                self.just_updated = true;
            }
        };
        Ok(true)
    }
}
