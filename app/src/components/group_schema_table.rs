use crate::{
    components::{
        delete_group_attribute::DeleteGroupAttribute,
        fragments::attribute_schema::render_attribute_name,
        router::{AppRoute, Link},
    },
    convert_attribute_type,
    infra::{
        attributes::group,
        common_component::{CommonComponent, CommonComponentParts},
        schema::AttributeType,
    },
};
use anyhow::{Error, Result, anyhow};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_attributes_schema.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupAttributesSchema;

use get_group_attributes_schema::ResponseData;

pub type Attribute =
    get_group_attributes_schema::GetGroupAttributesSchemaSchemaGroupSchemaAttributes;

convert_attribute_type!(get_group_attributes_schema::AttributeType);

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub hardcoded: bool,
}

pub struct GroupSchemaTable {
    common: CommonComponentParts<Self>,
    attributes: Option<Vec<Attribute>>,
}

pub enum Msg {
    ListAttributesResponse(Result<ResponseData>),
    OnAttributeDeleted(String),
    OnError(Error),
}

impl CommonComponent<GroupSchemaTable> for GroupSchemaTable {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ListAttributesResponse(schema) => {
                self.attributes =
                    Some(schema?.schema.group_schema.attributes.into_iter().collect());
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::OnAttributeDeleted(attribute_name) => match self.attributes {
                None => {
                    log!(format!(
                        "Attribute {attribute_name} was  deleted but component has no attributes"
                    ));
                    Err(anyhow!("invalid state"))
                }
                Some(_) => {
                    self.attributes
                        .as_mut()
                        .unwrap()
                        .retain(|a| a.name != attribute_name);
                    Ok(true)
                }
            },
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for GroupSchemaTable {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = GroupSchemaTable {
            common: CommonComponentParts::<Self>::create(),
            attributes: None,
        };
        table.common.call_graphql::<GetGroupAttributesSchema, _>(
            ctx,
            get_group_attributes_schema::Variables {},
            Msg::ListAttributesResponse,
            "Error trying to fetch group schema",
        );
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div>
              {self.view_attributes(ctx)}
              {self.view_errors()}
            </div>
        }
    }
}

impl GroupSchemaTable {
    fn view_attributes(&self, ctx: &Context<Self>) -> Html {
        let hardcoded = ctx.props().hardcoded;
        let make_table = |attributes: &Vec<Attribute>| {
            html! {
                <div class="table-responsive">
                    <h3>{if hardcoded {"Hardcoded"} else {"User-defined"}}{" attributes"}</h3>
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>{"Attribute name"}</th>
                                <th>{"Type"}</th>
                                <th>{"Visible"}</th>
                                {if hardcoded {html!{}} else {html!{<th>{"Delete"}</th>}}}
                            </tr>
                        </thead>
                        <tbody>
                            {attributes.iter().map(|u| self.view_attribute(ctx, u)).collect::<Vec<_>>()}
                        </tbody>
                    </table>
                </div>
            }
        };
        match &self.attributes {
            None => html! {{"Loading..."}},
            Some(attributes) => {
                let mut attributes = attributes.clone();
                attributes.retain(|attribute| attribute.is_hardcoded == ctx.props().hardcoded);
                make_table(&attributes)
            }
        }
    }

    fn view_attribute(&self, ctx: &Context<Self>, attribute: &Attribute) -> Html {
        let link = ctx.link();
        let attribute_type = AttributeType::from(attribute.attribute_type.clone());
        let checkmark = html! {
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check" viewBox="0 0 16 16">
          <path d="M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425z"></path>
        </svg>
                };
        let hardcoded = ctx.props().hardcoded;
        let desc = group::resolve_group_attribute_description_or_default(&attribute.name);
        html! {
            <tr key={attribute.name.clone()}>
                <td>{render_attribute_name(hardcoded, &desc)}</td>
                <td>{if attribute.is_list { format!("List<{attribute_type}>")} else {attribute_type.to_string()}}</td>
                <td>{if attribute.is_visible {checkmark.clone()} else {html!{}}}</td>
                {
                    if hardcoded {
                        html!{}
                    } else {
                        html!{
                            <td>
                                <DeleteGroupAttribute
                                    attribute_name={attribute.name.clone()}
                                    on_attribute_deleted={link.callback(Msg::OnAttributeDeleted)}
                                    on_error={link.callback(Msg::OnError)}/>
                            </td>
                        }
                    }
                }
            </tr>
        }
    }

    fn view_errors(&self) -> Html {
        match &self.common.error {
            None => html! {},
            Some(e) => html! {<div>{"Error: "}{e.to_string()}</div>},
        }
    }
}

#[function_component(ListGroupSchema)]
pub fn list_group_schema() -> Html {
    html! {
        <div>
            <GroupSchemaTable hardcoded={true} />
            <GroupSchemaTable hardcoded={false} />
            <Link classes="btn btn-primary" to={AppRoute::CreateGroupAttribute}>
                <i class="bi-plus-circle me-2"></i>
                {"Create an attribute"}
            </Link>
        </div>
    }
}
