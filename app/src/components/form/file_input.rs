use std::{fmt::Display, str::FromStr};

use anyhow::{Error, Ok, Result, bail};
use gloo_file::{
    File,
    callbacks::{FileReader, read_as_bytes},
};
use web_sys::{FileList, HtmlInputElement, InputEvent};
use yew::Properties;
use yew::{prelude::*, virtual_dom::AttrValue};

#[derive(Default)]
struct JsFile {
    file: Option<File>,
    contents: Option<Vec<u8>>,
}

impl Display for JsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.file.as_ref().map(File::name).unwrap_or_default()
        )
    }
}

impl FromStr for JsFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            Ok(JsFile::default())
        } else {
            bail!("Building file from non-empty string")
        }
    }
}

fn to_base64(file: &JsFile) -> Result<String> {
    match file {
        JsFile {
            file: None,
            contents: None,
        } => Ok(String::new()),
        JsFile {
            file: Some(_),
            contents: None,
        } => bail!("Image file hasn't finished loading, try again"),
        JsFile {
            file: Some(_),
            contents: Some(data),
        } => {
            if !is_valid_jpeg(data.as_slice()) {
                bail!("Chosen image is not a valid JPEG");
            }
            Ok(base64::encode(data))
        }
        JsFile {
            file: None,
            contents: Some(data),
        } => Ok(base64::encode(data)),
    }
}

/// A [yew::Component] to display the user details, with a form allowing to edit them.
pub struct JpegFileInput {
    // None means that the avatar hasn't changed.
    avatar: Option<JsFile>,
    reader: Option<FileReader>,
}

pub enum Msg {
    Update,
    /// A new file was selected.
    FileSelected(File),
    /// The "Clear" button for the avatar was clicked.
    ClearClicked,
    /// A picked file finished loading.
    FileLoaded(String, Result<Vec<u8>>),
}

#[derive(Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub name: AttrValue,
    pub value: Option<String>,
}

impl Component for JpegFileInput {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        Self {
            avatar: Some(JsFile {
                file: None,
                contents: ctx
                    .props()
                    .value
                    .as_ref()
                    .and_then(|x| base64::decode(x).ok()),
            }),
            reader: None,
        }
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        self.avatar = Some(JsFile {
            file: None,
            contents: ctx
                .props()
                .value
                .as_ref()
                .and_then(|x| base64::decode(x).ok()),
        });
        self.reader = None;
        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Update => true,
            Msg::FileSelected(new_avatar) => {
                if self
                    .avatar
                    .as_ref()
                    .and_then(|f| f.file.as_ref().map(|f| f.name()))
                    != Some(new_avatar.name())
                {
                    let file_name = new_avatar.name();
                    let link = ctx.link().clone();
                    self.reader = Some(read_as_bytes(&new_avatar, move |res| {
                        link.send_message(Msg::FileLoaded(
                            file_name,
                            res.map_err(|e| anyhow::anyhow!("{:#}", e)),
                        ))
                    }));
                    self.avatar = Some(JsFile {
                        file: Some(new_avatar),
                        contents: None,
                    });
                }
                true
            }
            Msg::ClearClicked => {
                self.avatar = Some(JsFile::default());
                true
            }
            Msg::FileLoaded(file_name, data) => {
                if let Some(avatar) = &mut self.avatar
                    && let Some(file) = &avatar.file
                    && file.name() == file_name
                    && let Result::Ok(data) = data
                {
                    if !is_valid_jpeg(data.as_slice()) {
                        // Clear the selection.
                        self.avatar = Some(JsFile::default());
                        // TODO: bail!("Chosen image is not a valid JPEG");
                    } else {
                        avatar.contents = Some(data);
                        return true;
                    }
                }
                self.reader = None;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();

        let avatar_string = match &self.avatar {
            Some(avatar) => {
                let avatar_base64 = to_base64(avatar);
                avatar_base64.as_deref().unwrap_or("").to_owned()
            }
            None => String::new(),
        };
        html! {
            <div class="row align-items-center">
                <div class="col-5">
                    <input type="hidden" name={ctx.props().name.clone()} value={avatar_string.clone()} />
                    <input
                        class="form-control"
                        id="avatarInput"
                        type="file"
                        accept="image/jpeg"
                        oninput={link.callback(|e: InputEvent| {
                            let input: HtmlInputElement = e.target_unchecked_into();
                            Self::upload_files(input.files())
                        })} />
                </div>
                <div class="col-3">
                    <button
                        class="btn btn-secondary col-auto"
                        id="avatarClear"
                        type="button"
                        onclick={link.callback(|_| {Msg::ClearClicked})}>
                        {"Clear"}
                        </button>
                </div>
                <div class="col-4">
                {
                    if !avatar_string.is_empty() {
                        html!{
                            <img
                            id="avatarDisplay"
                            src={format!("data:image/jpeg;base64, {}", avatar_string)}
                            style="max-height:128px;max-width:128px;height:auto;width:auto;"
                            alt="Avatar" />
                        }
                    } else { html! {} }
                }
                </div>
            </div>
        }
    }
}

impl JpegFileInput {
    fn upload_files(files: Option<FileList>) -> Msg {
        match files {
            Some(files) if files.length() > 0 => {
                Msg::FileSelected(File::from(files.item(0).unwrap()))
            }
            Some(_) | None => Msg::Update,
        }
    }
}

fn is_valid_jpeg(bytes: &[u8]) -> bool {
    image::io::Reader::with_format(std::io::Cursor::new(bytes), image::ImageFormat::Jpeg)
        .decode()
        .is_ok()
}
