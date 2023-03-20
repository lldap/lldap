use yew::prelude::*;

pub struct Select {
    node_ref: NodeRef,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct SelectProps {
    pub children: ChildrenWithProps<SelectOption>,
    pub on_selection_change: Callback<Option<SelectOptionProps>>,
}

pub enum SelectMsg {
    OnSelectChange,
}

impl Select {
    fn get_nth_child_props(&self, ctx: &Context<Self>, nth: i32) -> Option<SelectOptionProps> {
        if nth == -1 {
            return None;
        }
        ctx.props()
            .children
            .iter()
            .nth(nth as usize)
            .map(|child| (*child.props).clone())
    }

    fn send_selection_update(&self, ctx: &Context<Self>) {
        let select_node = self.node_ref.cast::<web_sys::HtmlSelectElement>().unwrap();
        ctx.props()
            .on_selection_change
            .emit(self.get_nth_child_props(ctx, select_node.selected_index()))
    }
}

impl Component for Select {
    type Message = SelectMsg;
    type Properties = SelectProps;
    fn create(_: &Context<Self>) -> Self {
        Self {
            node_ref: NodeRef::default(),
        }
    }

    fn rendered(&mut self, ctx: &Context<Self>, _first_render: bool) {
        self.send_selection_update(ctx);
    }

    fn update(&mut self, ctx: &Context<Self>, _: Self::Message) -> bool {
        self.send_selection_update(ctx);
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <select class="form-select"
              ref={self.node_ref.clone()}
              disabled={ctx.props().children.is_empty()}
              onchange={ctx.link().callback(|_| SelectMsg::OnSelectChange)}>
            { ctx.props().children.clone() }
            </select>
        }
    }
}

#[derive(yew::Properties, Clone, PartialEq, Eq, Debug)]
pub struct SelectOptionProps {
    pub value: String,
    pub text: String,
}

#[function_component(SelectOption)]
pub fn select_option(props: &SelectOptionProps) -> Html {
    html! {
      <option value={props.value.clone()}>
        {&props.text}
      </option>
    }
}
