use crate::{
    components::router::AppRoute,
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Result};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_user_attribute.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateUserAttribute;

type AttributeType = create_user_attribute::AttributeType;

pub struct CreateUserAttributeForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<CreateUserAttributeModel>,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default, Debug)]
pub struct CreateUserAttributeModel {
    #[validate(length(min = 1, message = "attribute_name is required"))]
    attribute_name: String,
    #[validate(length(min = 1, message = "attribute_type is required"))]
    attribute_type: String,
    is_editable: bool,
    is_list: bool,
    is_visible: bool,
}

pub enum Msg {
    Update,
    SubmitForm,
    CreateUserAttributeResponse(Result<create_user_attribute::ResponseData>),
}

impl CommonComponent<CreateUserAttributeForm> for CreateUserAttributeForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitForm => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let model = self.form.model();
                if model.is_editable && !model.is_visible {
                    bail!("Editable attributes must also be visible");
                }
                let attribute_type = match model.attribute_type.as_str() {
                    "Jpeg" => AttributeType::JPEG_PHOTO,
                    "DateTime" => AttributeType::DATE_TIME,
                    "Integer" => AttributeType::INTEGER,
                    "String" => AttributeType::STRING,
                    _ => bail!("Check the form for errors"),
                };
                let req = create_user_attribute::Variables {
                    name: model.attribute_name,
                    attribute_type,
                    is_editable: model.is_editable,
                    is_list: model.is_list,
                    is_visible: model.is_visible,
                };
                self.common.call_graphql::<CreateUserAttribute, _>(
                    ctx,
                    req,
                    Msg::CreateUserAttributeResponse,
                    "Error trying to create user attribute",
                );
                Ok(true)
            }
            Msg::CreateUserAttributeResponse(response) => {
                response?;
                let model = self.form.model();
                log!(&format!(
                    "Created user attribute '{}'",
                    model.attribute_name
                ));
                ctx.link()
                    .history()
                    .unwrap()
                    .push(AppRoute::ListUserAttributes);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateUserAttributeForm {
    type Message = Msg;
    type Properties = ();

    fn create(_: &Context<Self>) -> Self {
        let model = CreateUserAttributeModel {
            attribute_type: "String".to_string(),
            ..Default::default()
        };
        Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<CreateUserAttributeModel>::new(model),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        type Field = yew_form::Field<CreateUserAttributeModel>;
        type Select = yew_form::Select<CreateUserAttributeModel>;
        type Checkbox = yew_form::CheckBox<CreateUserAttributeModel>;
        html! {
          <div class="row justify-content-center">
            <form class="form py-3" style="max-width: 636px">
              <div class="row mb-3">
                <h5 class="fw-bold">{"Create a user attribute"}</h5>
              </div>
              <div class="form-group row mb-3">
                <label for="attribute_name"
                  class="form-label col-4 col-form-label">
                  {"Attribute name"}
                  <span class="text-danger">{"*"}</span>
                  {":"}
                </label>
                <div class="col-8">
                  <Field
                    form={&self.form}
                    field_name="attribute_name"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="attribute_name"
                    oninput={link.callback(|_| Msg::Update)} />
                  <div class="invalid-feedback">
                    {&self.form.field_message("attribute_name")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="attribute_type"
                  class="form-label col-4 col-form-label">
                  {"Type:"}
                </label>
                <div class="col-8">
                  <Select
                    form={&self.form}
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    field_name="attribute_type"
                    oninput={link.callback(|_| Msg::Update)} >
                    <option selected=true value="String">{"String"}</option>
                    <option value="Integer">{"Integer"}</option>
                    <option value="Jpeg">{"Jpeg"}</option>
                    <option value="DateTime">{"DateTime"}</option>
                  </Select>
                  <div class="invalid-feedback">
                    {&self.form.field_message("attribute_type")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="is_list"
                  class="form-label col-4 col-form-label">
                  {"Multiple values:"}
                </label>
                <div class="col-8">
                  <Checkbox
                    form={&self.form}
                    field_name="is_list"
                    ontoggle={link.callback(|_| Msg::Update)} />
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="is_visible"
                  class="form-label col-4 col-form-label">
                  {"Visible to users:"}
                </label>
                <div class="col-8">
                  <Checkbox
                    form={&self.form}
                    field_name="is_visible"
                    ontoggle={link.callback(|_| Msg::Update)} />
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="is_editable"
                  class="form-label col-4 col-form-label">
                  {"Editable by users:"}
                </label>
                <div class="col-8">
                  <Checkbox
                    form={&self.form}
                    field_name="is_editable"
                    ontoggle={link.callback(|_| Msg::Update)} />
                </div>
              </div>
              <div class="form-group row justify-content-center">
                <button
                  class="btn btn-primary col-auto col-form-label"
                  type="submit"
                  disabled={self.common.is_task_running()}
                  onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})}>
                  <i class="bi-save me-2"></i>
                  {"Submit"}
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
          </div>
        }
    }
}
