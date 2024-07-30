use std::{fmt::Display, str::FromStr};

use crate::{
    components::{
        form::{
            attribute_input::{SingleAttributeInput, ListAttributeInput},
            field::Field, static_value::StaticValue, submit::Submit,
        },
        user_details::{Attribute, AttributeSchema, User},
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        schema::AttributeType,
    },
};
use anyhow::{anyhow, bail, Error, Ok, Result};
use gloo_console::log;
use gloo_file::{
    callbacks::{read_as_bytes, FileReader},
    File,
};
use graphql_client::GraphQLQuery;
use validator::HasLen;
use validator_derive::Validate;
use web_sys::{FileList, FormData, HtmlFormElement, HtmlInputElement, InputEvent};
use yew::prelude::*;
use yew_form_derive::Model;

#[derive(Default)]
struct JsFile {
    file: Option<File>,
    contents: Option<Vec<u8>>,
}

impl Display for JsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.file.as_ref().map(File::name).unwrap_or_default()
        )
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
    form_ref: NodeRef,
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
    pub user_attributes_schema: Vec<AttributeSchema>,
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
        };
        Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::new(model),
            avatar: None,
            just_updated: false,
            reader: None,
            user: ctx.props().user.clone(),
            form_ref: NodeRef::default(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.just_updated = false;
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();

        let avatar_string = match &self.avatar {
            Some(avatar) => {
                let avatar_base64 = to_base64(avatar);
                avatar_base64.as_deref().unwrap_or("").to_owned()
            }
            None => String::new(), //self.user.avatar.as_deref().unwrap_or("").to_owned(),
        };
        html! {
          <div class="py-3">
            <form
              class="form"
              ref={self.form_ref.clone()}>
              <StaticValue label="User ID" id="userId">
                <i>{&self.user.id}</i>
              </StaticValue>
              <StaticValue label="Creation date" id="creationDate">
                {&self.user.creation_date.naive_local().date()}
              </StaticValue>
              <StaticValue label="UUID" id="uuid">
                {&self.user.uuid}
              </StaticValue>
              <Field<UserModel>
                form={&self.form}
                required=true
                label="Email"
                field_name="email"
                input_type="email"
                oninput={link.callback(|_| Msg::Update)} />
              <Field<UserModel>
                form={&self.form}
                label="Display name"
                field_name="display_name"
                autocomplete="name"
                oninput={link.callback(|_| Msg::Update)} />
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
              {ctx.props().user_attributes_schema.iter().filter(|a| a.is_editable).map(|s| get_custom_attribute_input(s, &self.user.attributes)).collect::<Vec<_>>()}
              <Submit
                text="Save changes"
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})} />
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

type AttributeValue = (String, Vec<String>);

fn get_values_from_form_data(
    schema: Vec<&AttributeSchema>,
    form: &FormData,
) -> Result<Vec<AttributeValue>> {
    schema
        .into_iter()
        .map(|attr| -> Result<AttributeValue> {
            let val = form
                .get_all(attr.name.as_str())
                .iter()
                .map(|js_val| js_val.as_string().unwrap_or_default())
                .filter(|val| !val.is_empty())
                .collect::<Vec<String>>();
            if val.length() > 1 && !attr.is_list {
                return Err(anyhow!(
                    "Multiple values supplied for non-list attribute {}",
                    attr.name
                ));
            }
            Ok((attr.name.clone(), val))
        })
        .collect()
}

fn get_custom_attribute_input(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
) -> Html {
    if attribute_schema.is_list {
        let values = user_attributes
            .iter()
            .find(|a| a.name == attribute_schema.name)
            .map(|attribute| attribute.value.clone())
            .unwrap_or_default();
        html! {<ListAttributeInput name={attribute_schema.name.clone()} attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())} values={values}/>}
    } else {
        let value = user_attributes
            .iter()
            .find(|a| a.name == attribute_schema.name)
            .and_then(|attribute| attribute.value.first().cloned())
            .unwrap_or_default();
        html! {<SingleAttributeInput name={attribute_schema.name.clone()} attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())} value={value}/>}
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
        let form = self.form_ref.cast::<HtmlFormElement>().unwrap();
        let form_data = FormData::new_with_form(&form)
            .map_err(|e| anyhow!("Failed to get FormData: {:#?}", e.as_string()))?;
        let mut all_values = get_values_from_form_data(
            ctx.props()
                .user_attributes_schema
                .iter()
                .filter(|attr| attr.is_editable)
                .collect(),
            &form_data,
        )?;
        let base_user = &self.user;
        let base_attributes = &self.user.attributes;
        log!(format!("base_attributes: {:#?}\nall_values: {:#?}", base_attributes, all_values));
        all_values.retain(|(name, val)| {
            let name = name.clone();
            let base_val = base_attributes
                .iter()
                .find(|base_val| base_val.name == name);
            let new_values = val.clone();
            base_val.map(|v| v.value != new_values).unwrap_or(!new_values.is_empty())
        });
        let remove_attributes: Option<Vec<String>> = if all_values.is_empty() {
            None
        } else {
            Some(all_values.iter().map(|(name, _)| name.clone()).collect())
        };
        let insert_attributes: Option<Vec<update_user::AttributeValueInput>> =
            if remove_attributes.is_none() {
                None
            } else {
                Some(
                    all_values
                        .into_iter()
                        .map(|(name, value)| update_user::AttributeValueInput { name, value })
                        .collect(),
                )
            };
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
        if let Some(avatar) = &self.avatar {
            user_input.avatar = Some(to_base64(avatar)?);
        }
        user_input.removeAttributes = remove_attributes;
        user_input.insertAttributes = insert_attributes;
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
        if let Some(avatar) = &self.avatar {
            //self.user.avatar = Some(to_base64(avatar)?);
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
