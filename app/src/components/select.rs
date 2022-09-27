use yew::{html::ChangeData, prelude::*};
use yewtil::NeqAssign;

pub struct Select {
    link: ComponentLink<Self>,
    props: SelectProps,
    node_ref: NodeRef,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct SelectProps {
    pub children: ChildrenWithProps<SelectOption>,
    pub on_selection_change: Callback<Option<SelectOptionProps>>,
}

pub enum SelectMsg {
    OnSelectChange(ChangeData),
}

impl Select {
    fn get_nth_child_props(&self, nth: i32) -> Option<SelectOptionProps> {
        if nth == -1 {
            return None;
        }
        self.props
            .children
            .iter()
            .nth(nth as usize)
            .map(|child| child.props)
    }

    fn send_selection_update(&self) {
        let select_node = self.node_ref.cast::<web_sys::HtmlSelectElement>().unwrap();
        self.props
            .on_selection_change
            .emit(self.get_nth_child_props(select_node.selected_index()))
    }
}

impl Component for Select {
    type Message = SelectMsg;
    type Properties = SelectProps;
    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            props,
            node_ref: NodeRef::default(),
        }
    }

    fn rendered(&mut self, _first_render: bool) {
        self.send_selection_update();
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        let SelectMsg::OnSelectChange(data) = msg;
        match data {
            ChangeData::Select(_) => self.send_selection_update(),
            _ => unreachable!(),
        }
        false
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.props.children.neq_assign(props.children)
    }

    fn view(&self) -> Html {
        html! {
            <select
              ref=self.node_ref.clone()
              disabled=self.props.children.is_empty()
              onchange=self.link.callback(SelectMsg::OnSelectChange)>
            { self.props.children.clone() }
            </select>
        }
    }
}

pub struct SelectOption {
    props: SelectOptionProps,
}

#[derive(yew::Properties, Clone, PartialEq, Eq, Debug)]
pub struct SelectOptionProps {
    pub value: String,
    pub text: String,
}

impl Component for SelectOption {
    type Message = ();
    type Properties = SelectOptionProps;

    fn create(props: Self::Properties, _: ComponentLink<Self>) -> Self {
        Self { props }
    }

    fn update(&mut self, _: Self::Message) -> ShouldRender {
        false
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.props.neq_assign(props)
    }

    fn view(&self) -> Html {
        html! {
          <option value=self.props.value.clone()>
            {&self.props.text}
          </option>
        }
    }
}
