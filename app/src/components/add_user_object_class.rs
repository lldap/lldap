use crate::{
    components::{
        form::{field::Field, submit::Submit},
        object_class_table::{ObjectClass, ObjectClassTable},
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result, anyhow, bail};
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/add_user_object_class.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct AddUserObjectClass;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_object_classes.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserObjectClasses;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_user_object_class.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteUserObjectClassQuery;

use add_user_object_class::ResponseData as AddResponseData;
use delete_user_object_class_query::ResponseData as DeleteResponseData;
use get_user_object_classes::ResponseData as ListResponseData;

#[derive(Model, Validate, PartialEq, Eq, Clone, Default, Debug)]
pub struct AddUserObjectClassModel {
    #[validate(length(min = 1, message = "object class is required"))]
    user_object_class: String,
}

pub enum Msg {
    Add,
    AddResponse(Result<AddResponseData>),
    Delete(String),
    DeleteResponse(String, Result<DeleteResponseData>),
    ListResponse(Result<ListResponseData>),
    Update,
    OnError(Error),
}

pub struct ListUserObjectClass {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<AddUserObjectClassModel>,
    form_version: usize,
    object_classes: Option<Vec<ObjectClass>>,
}

impl CommonComponent<ListUserObjectClass> for ListUserObjectClass {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::Add => {
                let model = self.form.model();
                if !self.form.validate() {
                    bail!("A user object class name is required");
                }
                self.ensure_object_class_is_new(&model.user_object_class)?;
                self.common.call_graphql::<AddUserObjectClass, _>(
                    ctx,
                    add_user_object_class::Variables {
                        name: model.user_object_class,
                    },
                    Msg::AddResponse,
                    "Error trying to add user object class",
                );
                Ok(true)
            }
            Msg::AddResponse(response) => {
                response?;
                self.form = yew_form::Form::new(AddUserObjectClassModel::default());
                self.form_version += 1;
                self.fetch_object_classes(ctx);
                Ok(true)
            }
            Msg::Delete(object_class) => {
                self.common.call_graphql::<DeleteUserObjectClassQuery, _>(
                    ctx,
                    delete_user_object_class_query::Variables {
                        name: object_class.clone(),
                    },
                    move |response| Msg::DeleteResponse(object_class.clone(), response),
                    "Error trying to delete user object class",
                );
                Ok(true)
            }
            Msg::DeleteResponse(object_class, response) => {
                response?;
                let object_classes = self
                    .object_classes
                    .as_mut()
                    .ok_or_else(|| anyhow!("object classes have not loaded"))?;
                object_classes.retain(|class| class.name != object_class);
                Ok(true)
            }
            Msg::ListResponse(response) => {
                self.object_classes = Some(
                    response?
                        .schema
                        .user_schema
                        .ldap_object_classes
                        .into_iter()
                        .map(|class| ObjectClass {
                            name: class.object_class,
                            is_hardcoded: class.is_hardcoded,
                        })
                        .collect(),
                );
                Ok(true)
            }
            Msg::OnError(error) => Err(error),
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ListUserObjectClass {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::new(AddUserObjectClassModel::default()),
            form_version: 0,
            object_classes: None,
        };
        component.fetch_object_classes(ctx);
        component
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        html! {
            <div>
                <ObjectClassTable
                    object_classes={self.object_classes.clone()}
                    delete_disabled={self.common.is_task_running()}
                    on_delete={link.callback(Msg::Delete)} />
                <form class="form py-3" style="max-width: 636px">
                    <h5 class="fw-bold">{"Add a user object class"}</h5>
                    <Field<AddUserObjectClassModel>
                        key={self.form_version}
                        label="Name"
                        required={true}
                        form={&self.form}
                        field_name="user_object_class"
                        oninput={link.callback(|_| Msg::Update)} />
                    <Submit
                        disabled={self.common.is_task_running()}
                        text="Add object class"
                        onclick={link.callback(|event: MouseEvent| {
                            event.prevent_default();
                            Msg::Add
                        })}/>
                </form>
                {self.view_errors()}
            </div>
        }
    }
}

impl ListUserObjectClass {
    fn fetch_object_classes(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetUserObjectClasses, _>(
            ctx,
            get_user_object_classes::Variables {},
            Msg::ListResponse,
            "Error trying to fetch user object classes",
        );
    }

    fn ensure_object_class_is_new(&self, name: &str) -> Result<()> {
        if self.object_classes.as_ref().is_some_and(|classes| {
            classes
                .iter()
                .any(|class| class.name.eq_ignore_ascii_case(name))
        }) {
            bail!("User object class '{name}' already exists");
        }
        Ok(())
    }

    fn view_errors(&self) -> Html {
        match &self.common.error {
            None => html! {},
            Some(error) => html! {<div class="alert alert-danger">{error.to_string()}</div>},
        }
    }
}
