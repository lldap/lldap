use crate::{
    components::router::AppRoute,
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Result};
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use yew::prelude::*;
use yew::services::ConsoleService;
use yew_form_derive::Model;
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateGroup;

pub struct CreateGroupForm {
    common: CommonComponentParts<Self>,
    route_dispatcher: RouteAgentDispatcher,
    form: yew_form::Form<CreateGroupModel>,
}

#[derive(Model, Validate, PartialEq, Clone, Default)]
pub struct CreateGroupModel {
    #[validate(length(min = 1, message = "Groupname is required"))]
    groupname: String,
}

pub enum Msg {
    Update,
    SubmitForm,
    CreateGroupResponse(Result<create_group::ResponseData>),
}

impl CommonComponent<CreateGroupForm> for CreateGroupForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitForm => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let model = self.form.model();
                let req = create_group::Variables {
                    name: model.groupname,
                };
                self.common.call_graphql::<CreateGroup, _>(
                    req,
                    Msg::CreateGroupResponse,
                    "Error trying to create group",
                );
                Ok(true)
            }
            Msg::CreateGroupResponse(response) => {
                ConsoleService::log(&format!(
                    "Created group '{}'",
                    &response?.create_group.display_name
                ));
                self.route_dispatcher
                    .send(RouteRequest::ChangeRoute(Route::from(AppRoute::ListGroups)));
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateGroupForm {
    type Message = Msg;
    type Properties = ();

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(props, link),
            route_dispatcher: RouteAgentDispatcher::new(),
            form: yew_form::Form::<CreateGroupModel>::new(CreateGroupModel::default()),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        type Field = yew_form::Field<CreateGroupModel>;
        html! {
          <div class="row justify-content-center">
            <form class="form shadow-sm py-3" style="max-width: 636px">
              <div class="row mb-3">
                <h5 class="fw-bold">{"Create a group"}</h5>
              </div>
              <div class="form-group row mb-3">
                <label for="groupname"
                  class="form-label col-4 col-form-label">
                  {"Group name*:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    field_name="groupname"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="groupname"
                    oninput=self.common.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("groupname")}
                  </div>
                </div>
              </div>
              <div class="form-group row justify-content-center">
                <button
                  class="btn btn-primary col-auto col-form-label"
                  type="submit"
                  disabled=self.common.is_task_running()
                  onclick=self.common.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})>
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
