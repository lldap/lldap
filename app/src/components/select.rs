use yew::{html::ChangeData, prelude::*};

pub struct Select {
    link: ComponentLink<Self>,
    props: SelectProps,
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
}

impl Component for Select {
    type Message = SelectMsg;
    type Properties = SelectProps;
    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let res = Self { link, props };
        res.props
            .on_selection_change
            .emit(res.get_nth_child_props(0));
        res
    }
    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            SelectMsg::OnSelectChange(data) => match data {
                ChangeData::Select(e) => {
                    self.props
                        .on_selection_change
                        .emit(self.get_nth_child_props(e.selected_index()));
                }
                _ => unreachable!(),
            },
        }
        false
    }
    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        if self.props.children.len() != props.children.len() {
            let was_empty = self.props.children.is_empty();
            self.props = props;
            if self.props.children.is_empty() || was_empty {
                self.props
                    .on_selection_change
                    .emit(self.get_nth_child_props(0));
            }
            true
        } else {
            false
        }
    }
    fn view(&self) -> Html {
        html! {
            <select
                  onchange=self.link.callback(SelectMsg::OnSelectChange)>
            { self.props.children.clone() }
            </select>
        }
    }
}

pub struct SelectOption {
    props: SelectOptionProps,
}

#[derive(yew::Properties, Clone, PartialEq)]
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
        if self.props != props {
            self.props = props;
            true
        } else {
            false
        }
    }
    fn view(&self) -> Html {
        html! {
          <option value=self.props.value.clone()>
            {&self.props.text}
          </option>
        }
    }
}
