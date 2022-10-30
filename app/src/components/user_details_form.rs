use std::str::FromStr;

use crate::{
    components::user_details::User,
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Error, Result};
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use wasm_bindgen::JsCast;
use yew::{prelude::*, services::ConsoleService};
use yew_form_derive::Model;

#[derive(PartialEq, Eq, Clone, Default)]
struct JsFile {
    file: Option<web_sys::File>,
    contents: Option<Vec<u8>>,
}

impl ToString for JsFile {
    fn to_string(&self) -> String {
        self.file
            .as_ref()
            .map(web_sys::File::name)
            .unwrap_or_else(String::new)
    }
}

impl FromStr for JsFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            Ok(JsFile::default())
        } else {
            bail!("Building file from non-empty string")
        }
    }
}

/// The fields of the form, with the editable details and the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone)]
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
variables_derives = "Clone,PartialEq,Eq",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdateUser;

/// A [yew::Component] to display the user details, with a form allowing to edit them.
pub struct UserDetailsForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<UserModel>,
    avatar: JsFile,
    /// True if we just successfully updated the user, to display a success message.
    just_updated: bool,
}

pub enum Msg {
    /// A form field changed.
    Update,
    /// The "Submit" button was clicked.
    SubmitClicked,
    /// A picked file finished loading.
    FileLoaded(yew::services::reader::FileData),
    /// We got the response from the server about our update message.
    UserUpdated(Result<update_user::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    /// The current user details.
    pub user: User,
}

impl CommonComponent<UserDetailsForm> for UserDetailsForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::Update => {
                let window = web_sys::window().expect("no global `window` exists");
                let document = window.document().expect("should have a document on window");
                let input = document
                    .get_element_by_id("avatarInput")
                    .expect("Form field avatarInput should be present")
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .expect("Should be an HtmlInputElement");
                ConsoleService::log("Form update");
                if let Some(files) = input.files() {
                    ConsoleService::log("Got file list");
                    if files.length() > 0 {
                        ConsoleService::log("Got a file");
                        let new_avatar = JsFile {
                            file: files.item(0),
                            contents: None,
                        };
                        if self.avatar.file.as_ref().map(|f| f.name())
                            != new_avatar.file.as_ref().map(|f| f.name())
                        {
                            if let Some(ref file) = new_avatar.file {
                                self.mut_common().read_file(file.clone(), Msg::FileLoaded)?;
                            }
                            self.avatar = new_avatar;
                        }
                    }
                }
                Ok(true)
            }
            Msg::SubmitClicked => self.submit_user_update_form(),
            Msg::UserUpdated(response) => self.user_update_finished(response),
            Msg::FileLoaded(data) => {
                self.common.cancel_task();
                if let Some(file) = &self.avatar.file {
                    if file.name() == data.name {
                        if !is_valid_jpeg(data.content.as_slice()) {
                            // Clear the selection.
                            self.avatar = JsFile::default();
                            bail!("Chosen image is not a valid JPEG");
                        } else {
                            self.avatar.contents = Some(data.content);
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
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
            avatar: JsFile::default(),
            just_updated: false,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.just_updated = false;
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        type Field = yew_form::Field<UserModel>;

        let avatar_base64 = maybe_to_base64(&self.avatar).unwrap_or_default();
        let avatar_string = avatar_base64.as_ref().unwrap_or(&self.common.user.avatar);
        html! {
          <div class="py-3">
            <form class="form">
            <div class="form-group row mb-3">
                <label for="userId"
                  class="form-label col-4 col-form-label">
                  {"User ID: "}
                </label>
                <div class="col-8">
                  <span id="userId" class="form-control-static"><i>{&self.common.user.id}</i></span>
                </div>
              </div>
            <div class="form-group row mb-3">
                <label for="creationDate"
                class="form-label col-4 col-form-label">
                {"Creation date: "}
                </label>
                <div class="col-8">
                  <span id="creationDate" class="form-control-static">{&self.common.user.creation_date.date().naive_local()}</span>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="uuid"
                class="form-label col-4 col-form-label">
                {"UUID: "}
                </label>
                <div class="col-8">
                  <span id="creationDate" class="form-control-static">{&self.common.user.uuid}</span>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="email"
                  class="form-label col-4 col-form-label">
            {"Email"}
            <span class="text-danger">{"*"}</span>
            {":"}
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
                  {"Display Name"}
             <span class="text-danger">{"*"}</span>
            {":"}
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
            <div class="form-group row align-items-center mb-3">
                <label for="avatar"
                  class="form-label col-4 col-form-label">
                  {"Avatar: "}
                </label>
                <div class="col-8">
            <div class="row align-items-center">
            <div class="col-8">
                   <input
                    class="form-control"
                    id="avatarInput"
                    type="file"
                    accept="image/jpeg"
                    oninput=self.common.callback(|_| Msg::Update) />
            </div>
            <div class="col-4">
                        <img
                    id="avatarDisplay"
                    src={format!("data:image/jpeg;base64, {}", avatar_string)}
                    style="max-height:128px;max-width:128px;height:auto;width:auto;"
                    alt="Avatar" />
            </div>
            </div>
            </div>
              </div>
              <div class="form-group row justify-content-center mt-3">
                <button
                  type="submit"
                  class="btn btn-primary col-auto col-form-label"
                  disabled=self.common.is_task_running()
                  onclick=self.common.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})>
              <i class="bi-save me-2"></i>
                  {"Save changes"}
                </button>
              </div>
            </form>
            { if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            <div hidden=!self.just_updated>
              <div class="alert alert-success mt-4">{"User successfully updated!"}</div>
            </div>
          </div>
        }
    }
}

impl UserDetailsForm {
    fn submit_user_update_form(&mut self) -> Result<bool> {
        ConsoleService::log("Submit");
        if !self.form.validate() {
            bail!("Invalid inputs");
        }
        ConsoleService::log("Valid inputs");
        if let JsFile {
            file: Some(_),
            contents: None,
        } = &self.avatar
        {
            bail!("Image file hasn't finished loading, try again");
        }
        ConsoleService::log("File is correctly loaded");
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
        user_input.avatar = maybe_to_base64(&self.avatar)?;
        // Nothing changed.
        if user_input == default_user_input {
            ConsoleService::log("No changes");
            return Ok(false);
        }
        let req = update_user::Variables { user: user_input };
        ConsoleService::log("Querying");
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
                self.common.user.email = model.email;
                self.common.user.display_name = model.display_name;
                self.common.user.first_name = model.first_name;
                self.common.user.last_name = model.last_name;
                if let Some(avatar) = maybe_to_base64(&self.avatar)? {
                    self.common.user.avatar = avatar;
                }
                self.just_updated = true;
            }
        };
        Ok(true)
    }
}

fn is_valid_jpeg(bytes: &[u8]) -> bool {
    image::io::Reader::with_format(std::io::Cursor::new(bytes), image::ImageFormat::Jpeg)
        .decode()
        .is_ok()
}

fn maybe_to_base64(file: &JsFile) -> Result<Option<String>> {
    match file {
        JsFile {
            file: None,
            contents: _,
        } => Ok(None),
        JsFile {
            file: Some(_),
            contents: None,
        } => bail!("Image file hasn't finished loading, try again"),
        JsFile {
            file: Some(_),
            contents: Some(data),
        } => {
            if !is_valid_jpeg(data.as_slice()) {
                bail!("Chosen image is not a valid JPEG");
            }
            Ok(Some(base64::encode(data)))
        }
    }
}
