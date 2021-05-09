use anyhow::{anyhow, Error};
use lldap_model::*;

use yew::callback::Callback;
use yew::format::Json;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};

#[derive(Default)]
pub struct HostService {}

impl HostService {
        pub fn list_users(&mut self, request: ListUsersRequest, callback: Callback<Result<Vec<User>, Error>>) -> Result<FetchTask, Error> {
        let url = format!("/api/users");
        let handler = move |response: Response<Json<Result<Vec<User>, Error>>>| {
            let (meta, Json(data)) = response.into_parts();
            if meta.status.is_success() {
                callback.emit(data)
            } else {
                callback.emit(Err(anyhow!(
                    "{}: error getting users from /api/users",
                    meta.status
                )))
            }
        };
        let request = Request::post(url.as_str()).header("Content-Type", "application/json").body(Json(&request)).unwrap();
        FetchService::fetch(request, handler.into())
    }
}

