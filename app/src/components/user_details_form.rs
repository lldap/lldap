use std::str::FromStr;

use crate::{
    components::user_details::User,
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Error, Result};
use gloo_file::{
    callbacks::{read_as_bytes, FileReader},
    File,
};
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use web_sys::{FileList, HtmlInputElement, InputEvent};
use yew::prelude::*;
use yew_form_derive::Model;

#[derive(Default)]
struct JsFile {
    file: Option<File>,
    contents: Option<Vec<u8>>,
}

impl ToString for JsFile {
    fn to_string(&self) -> String {
        self.file
            .as_ref()
            .map(File::name)
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
    // None means that the avatar hasn't changed.
    avatar: Option<JsFile>,
    reader: Option<FileReader>,
    /// True if we just successfully updated the user, to display a success message.
    just_updated: bool,
    user: User,
}

pub enum Msg {
    /// A form field changed.
    Update,
    /// A new file was selected.
    FileSelected(File),
    /// The "Submit" button was clicked.
    SubmitClicked,
    /// The "Clear" button for the avatar was clicked.
    ClearAvatarClicked,
    /// A picked file finished loading.
    FileLoaded(String, Result<Vec<u8>>),
    /// We got the response from the server about our update message.
    UserUpdated(Result<update_user::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    /// The current user details.
    pub user: User,
}

impl CommonComponent<UserDetailsForm> for UserDetailsForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::FileSelected(new_avatar) => {
                if self
                    .avatar
                    .as_ref()
                    .and_then(|f| f.file.as_ref().map(|f| f.name()))
                    != Some(new_avatar.name())
                {
                    let file_name = new_avatar.name();
                    let link = ctx.link().clone();
                    self.reader = Some(read_as_bytes(&new_avatar, move |res| {
                        link.send_message(Msg::FileLoaded(
                            file_name,
                            res.map_err(|e| anyhow::anyhow!("{:#}", e)),
                        ))
                    }));
                    self.avatar = Some(JsFile {
                        file: Some(new_avatar),
                        contents: None,
                    });
                }
                Ok(true)
            }
            Msg::SubmitClicked => self.submit_user_update_form(ctx),
            Msg::ClearAvatarClicked => {
                self.avatar = Some(JsFile::default());
                Ok(true)
            }
            Msg::UserUpdated(response) => self.user_update_finished(response),
            Msg::FileLoaded(file_name, data) => {
                if let Some(avatar) = &mut self.avatar {
                    if let Some(file) = &avatar.file {
                        if file.name() == file_name {
                            let data = data?;
                            if !is_valid_jpeg(data.as_slice()) {
                                // Clear the selection.
                                self.avatar = None;
                                bail!("Chosen image is not a valid JPEG");
                            } else {
                                avatar.contents = Some(data);
                                return Ok(true);
                            }
                        }
                    }
                }
                self.reader = None;
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

    fn create(ctx: &Context<Self>) -> Self {
        let model = UserModel {
            email: ctx.props().user.email.clone(),
            display_name: ctx.props().user.display_name.clone(),
            first_name: ctx.props().user.first_name.clone(),
            last_name: ctx.props().user.last_name.clone(),
        };
        Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::new(model),
            avatar: None,
            just_updated: false,
            reader: None,
            user: ctx.props().user.clone(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.just_updated = false;
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<UserModel>;
        let link = &ctx.link();

        let avatar_string = match &self.avatar {
            Some(avatar) => {
                let avatar_base64 = to_base64(avatar);
                avatar_base64.as_deref().unwrap_or("").to_owned()
            }
            None => self.user.avatar.as_deref().unwrap_or("").to_owned(),
        };
        html! {
          <div class="py-3">
            <form class="form">
              <div class="form-group row mb-3">
                <label for="userId"
                  class="form-label col-4 col-form-label">
                  {"User ID: "}
                </label>
                <div class="col-8">
                  <span id="userId" class="form-control-static"><i>{&self.user.id}</i></span>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="creationDate"
                  class="form-label col-4 col-form-label">
                  {"Creation date: "}
                </label>
                <div class="col-8">
                  <span id="creationDate" class="form-control-static">{&self.user.creation_date.naive_local().date()}</span>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="uuid"
                  class="form-label col-4 col-form-label">
                  {"UUID: "}
                </label>
                <div class="col-8">
                  <span id="creationDate" class="form-control-static">{&self.user.uuid}</span>
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
                    form={&self.form}
                    field_name="email"
                    autocomplete="email"
                    oninput={link.callback(|_| Msg::Update)} />
                  <div class="invalid-feedback">
                    {&self.form.field_message("email")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="display_name"
                  class="form-label col-4 col-form-label">
                  {"Display Name: "}
                </label>
                <div class="col-8">
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form={&self.form}
                    field_name="display_name"
                    autocomplete="name"
                    oninput={link.callback(|_| Msg::Update)} />
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
                    form={&self.form}
                    field_name="first_name"
                    autocomplete="given-name"
                    oninput={link.callback(|_| Msg::Update)} />
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
                    form={&self.form}
                    field_name="last_name"
                    autocomplete="family-name"
                    oninput={link.callback(|_| Msg::Update)} />
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
                    <div class="col-5">
                      <input
                        class="form-control"
                        id="avatarInput"
                        type="file"
                        accept="image/jpeg"
                        oninput={link.callback(|e: InputEvent| {
                            let input: HtmlInputElement = e.target_unchecked_into();
                            Self::upload_files(input.files())
                        })} />
                    </div>
                    <div class="col-3">
                      <button
                        class="btn btn-secondary col-auto"
                        id="avatarClear"
                        disabled={self.common.is_task_running()}
                        onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::ClearAvatarClicked})}>
                      {"Clear"}
                      </button>
                    </div>
                    <div class="col-4">
                    {
                      if !avatar_string.is_empty() {
                        html!{
                          <img
                            id="avatarDisplay"
                            src={format!("data:image/jpeg;base64, {}", avatar_string)}
                            style="max-height:128px;max-width:128px;height:auto;width:auto;"
                            alt="Avatar" />
                        }
                      } else { html! {} }
                    }
                    </div>
                  </div>
                </div>
              </div>
              <div class="form-group row justify-content-center mt-3">
                <button
                  type="submit"
                  class="btn btn-primary col-auto col-form-label"
                  disabled={self.common.is_task_running()}
                  onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})}>
                  <i class="bi-save me-2"></i>
                  {"Save changes"}
                </button>
              </div>
            </form>
            {
              if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            <div hidden={!self.just_updated}>
              <div class="alert alert-success mt-4">{"User successfully updated!"}</div>
            </div>
          </div>
        }
    }
}

impl UserDetailsForm {
    fn submit_user_update_form(&mut self, ctx: &Context<Self>) -> Result<bool> {
        if !self.form.validate() {
            bail!("Invalid inputs");
        }
        if let Some(JsFile {
            file: Some(_),
            contents: None,
        }) = &self.avatar
        {
            bail!("Image file hasn't finished loading, try again");
        }
        let base_user = &self.user;
        let mut user_input = update_user::UpdateUserInput {
            id: self.user.id.clone(),
            email: None,
            displayName: None,
            firstName: None,
            lastName: None,
            avatar: None,
            removeAttributes: None,
            insertAttributes: None,
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
        if let Some(avatar) = &self.avatar {
            user_input.avatar = Some(to_base64(avatar)?);
        }
        // Nothing changed.
        if user_input == default_user_input {
            return Ok(false);
        }
        let req = update_user::Variables { user: user_input };
        self.common.call_graphql::<UpdateUser, _>(
            ctx,
            req,
            Msg::UserUpdated,
            "Error trying to update user",
        );
        Ok(false)
    }

    fn user_update_finished(&mut self, r: Result<update_user::ResponseData>) -> Result<bool> {
        r?;
        let model = self.form.model();
        self.user.email = model.email;
        self.user.display_name = model.display_name;
        self.user.first_name = model.first_name;
        self.user.last_name = model.last_name;
        if let Some(avatar) = &self.avatar {
            self.user.avatar = Some(to_base64(avatar)?);
        }
        self.just_updated = true;
        Ok(true)
    }

    fn upload_files(files: Option<FileList>) -> Msg {
        if let Some(files) = files {
            if files.length() > 0 {
                Msg::FileSelected(File::from(files.item(0).unwrap()))
            } else {
                Msg::Update
            }
        } else {
            Msg::Update
        }
    }
}

fn is_valid_jpeg(bytes: &[u8]) -> bool {
    image::io::Reader::with_format(std::io::Cursor::new(bytes), image::ImageFormat::Jpeg)
        .decode()
        .is_ok()
}

fn to_base64(file: &JsFile) -> Result<String> {
    match file {
        JsFile {
            file: None,
            contents: _,
        } => Ok(String::new()),
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
            Ok(base64::encode(data))
        }
    }
}
