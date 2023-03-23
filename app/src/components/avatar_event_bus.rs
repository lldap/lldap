use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use yew_agent::{Agent, AgentLink, Context, HandlerId};

use super::avatar::AvatarData;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Update((String, Option<AvatarData>)),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Update((String, Option<AvatarData>)),
}

pub struct AvatarEventBus {
    link: AgentLink<AvatarEventBus>,
    subscribers: HashSet<HandlerId>,
}

impl Agent for AvatarEventBus {
    type Reach = Context<Self>;
    type Message = ();
    type Input = Request;
    type Output = Response;

    fn create(link: AgentLink<Self>) -> Self {
        Self {
            link,
            subscribers: HashSet::new(),
        }
    }

    fn update(&mut self, _msg: Self::Message) {}

    fn handle_input(&mut self, msg: Self::Input, _id: HandlerId) {
        match msg {
            Request::Update((username, avatar)) => {
                for sub in self.subscribers.iter() {
                    self.link
                        .respond(*sub, Response::Update((username.clone(), avatar.clone())));
                }
            }
        }
    }

    fn connected(&mut self, id: HandlerId) {
        self.subscribers.insert(id);
    }

    fn disconnected(&mut self, id: HandlerId) {
        self.subscribers.remove(&id);
    }
}
