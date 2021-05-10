use anyhow::Result;
use lldap_model::*;

use yew::callback::Callback;
use yew::format::Json;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};

#[derive(Default)]
pub struct HostService {}

impl HostService {
    pub fn list_users(
        &mut self,
        request: ListUsersRequest,
        callback: Callback<Result<Vec<User>>>,
    ) -> Result<FetchTask> {
        let url = format!("/api/users");
        let handler =
            move |response: Response<Result<String>>| {
                let (meta, maybe_data) = response.into_parts();
                match maybe_data {
                    Ok(data) => {
                        if meta.status.is_success() {
                            callback.emit(serde_json::from_str(&data).map_err(|e| {
                                anyhow::format_err!("Could not parse response: {}", e)
                            }))
                        } else {
                            callback.emit(Err(anyhow::anyhow!("[{}]: {}", meta.status, data)))
                        }
                    }
                    Err(e) => callback.emit(Err(anyhow::anyhow!("Could not fetch: {}", e))),
                }
            };
        let request = Request::post(url.as_str())
            .header("Content-Type", "application/json")
            .body(Json(&request))
            .unwrap();
        FetchService::fetch(request, handler.into())
    }
}
