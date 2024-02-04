use crate::infra::functional::{use_graphql_call, LoadableResult};
use graphql_client::GraphQLQuery;
use yew::{function_component, html, virtual_dom::AttrValue, Properties};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_details.graphql",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserDetails;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub user: AttrValue,
    #[prop_or(32)]
    pub width: i32,
    #[prop_or(32)]
    pub height: i32,
}

#[function_component(Avatar)]
pub fn avatar(props: &Props) -> Html {
    let user_details = use_graphql_call::<GetUserDetails>(get_user_details::Variables {
        id: props.user.to_string(),
    });

    match &(*user_details) {
        LoadableResult::Loaded(Ok(response)) => {
            let avatar = response.user.avatar.clone();
            match &avatar {
                Some(data) => html! {
                  <img
                    id="avatarDisplay"
                    src={format!("data:image/jpeg;base64, {}", data)}
                    style={format!("max-height:{}px;max-width:{}px;height:auto;width:auto;", props.height, props.width)}
                    alt="Avatar" />
                },
                None => html! {
                  <BlankAvatarDisplay
                    width={props.width}
                    height={props.height} />
                },
            }
        }
        LoadableResult::Loaded(Err(error)) => html! {
          <BlankAvatarDisplay
            error={error.to_string()}
            width={props.width}
            height={props.height} />
        },
        LoadableResult::Loading => html! {
          <BlankAvatarDisplay
            width={props.width}
            height={props.height} />
        },
    }
}

#[derive(Properties, PartialEq)]
struct BlankAvatarDisplayProps {
    #[prop_or(None)]
    pub error: Option<AttrValue>,
    pub width: i32,
    pub height: i32,
}

#[function_component(BlankAvatarDisplay)]
fn blank_avatar_display(props: &BlankAvatarDisplayProps) -> Html {
    let fill = match &props.error {
        Some(_) => "red",
        None => "currentColor",
    };
    html! {
      <svg xmlns="http://www.w3.org/2000/svg"
        width={props.width.to_string()}
        height={props.height.to_string()}
        fill={fill}
        class="bi bi-person-circle"
        viewBox="0 0 16 16">
        <title>{props.error.clone().unwrap_or(AttrValue::Static("Avatar"))}</title>
        <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
        <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
      </svg>
    }
}
