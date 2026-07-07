use crate::infra::{
    api::HostService,
    common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Result, anyhow};
use lldap_frontend_options::{BrandingOptions, ThemeMode};
use web_sys::{File, HtmlInputElement};
use yew::prelude::*;

/// The fields shown in the admin branding settings form.
#[derive(Clone, PartialEq, Default)]
struct SettingsFormModel {
    application_name: String,
    accent_color_hex: String,
    logo_url: String,
    logo_file_has_been_uploaded: bool,
    default_theme: ThemeMode,
    /// The user has selected a new file to upload.
    pending_logo_file: Option<web_sys::File>,
}

pub struct AdminSettingsForm {
    common: CommonComponentParts<Self>,
    form_model: SettingsFormModel,
    is_saving: bool,
    success_message: Option<String>,
}

#[derive(Properties, PartialEq, Clone)]
pub struct AdminSettingsFormProps {}

pub enum AdminSettingsFormMessage {
    SettingsFetched(Result<lldap_frontend_options::Options>),
    UpdateApplicationName(String),
    UpdateAccentColor(String),
    UpdateLogoUrl(String),
    UpdateDefaultTheme(String),
    FileSelected(Option<File>),
    RemoveLogo,
    SaveSettings,
    SettingsSaved(Result<lldap_frontend_options::Options>),
}

impl CommonComponent<AdminSettingsForm> for AdminSettingsForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            AdminSettingsFormMessage::SettingsFetched(Ok(settings)) => {
                let branding = settings.branding;
                self.form_model = SettingsFormModel {
                    application_name: branding.app_name,
                    accent_color_hex: branding.accent_color.unwrap_or_default(),
                    logo_url: branding.logo_url.unwrap_or_default(),
                    logo_file_has_been_uploaded: branding.logo_file_has_been_uploaded,
                    default_theme: branding.default_theme,
                    pending_logo_file: None,
                };
                Ok(true)
            }
            AdminSettingsFormMessage::SettingsFetched(Err(error_message)) => {
                self.common.error = Some(error_message);
                Ok(true)
            }
            AdminSettingsFormMessage::UpdateApplicationName(value) => {
                self.form_model.application_name = value;
                Ok(true)
            }
            AdminSettingsFormMessage::UpdateAccentColor(value) => {
                self.form_model.accent_color_hex = value;
                Ok(true)
            }
            AdminSettingsFormMessage::UpdateLogoUrl(value) => {
                self.form_model.logo_url = value;
                Ok(true)
            }
            AdminSettingsFormMessage::UpdateDefaultTheme(value) => {
                self.form_model.default_theme = match value.as_str() {
                    "light" => ThemeMode::Light,
                    "dark" => ThemeMode::Dark,
                    _ => ThemeMode::Auto,
                };
                Ok(true)
            }
            AdminSettingsFormMessage::FileSelected(file_option) => {
                self.form_model.pending_logo_file = file_option;
                Ok(true)
            }
            AdminSettingsFormMessage::RemoveLogo => {
                self.form_model.logo_file_has_been_uploaded = false;
                self.form_model.pending_logo_file = None;
                self.common
                    .call_backend(ctx, HostService::delete_logo(), |result| {
                        AdminSettingsFormMessage::SettingsSaved(result.map(|branding| {
                            lldap_frontend_options::Options {
                                password_reset_enabled: false,
                                branding,
                            }
                        }))
                    });
                Ok(true)
            }
            AdminSettingsFormMessage::SaveSettings => {
                if self.is_saving {
                    return Ok(false);
                }
                self.is_saving = true;
                self.success_message = None;
                self.common.error = None;

                let has_pending_file = self.form_model.pending_logo_file.is_some();

                let accent_color = if self.form_model.accent_color_hex.is_empty() {
                    None
                } else {
                    Some(self.form_model.accent_color_hex.clone())
                };

                let logo_url_value = if self.form_model.logo_url.is_empty() {
                    None
                } else {
                    Some(self.form_model.logo_url.clone())
                };

                let branding_payload = BrandingOptions {
                    app_name: self.form_model.application_name.clone(),
                    accent_color,
                    logo_url: logo_url_value,
                    logo_file_has_been_uploaded: self.form_model.logo_file_has_been_uploaded,
                    default_theme: self.form_model.default_theme,
                };

                if has_pending_file {
                    let file = self.form_model.pending_logo_file.clone().unwrap();
                    let file_name = file.name();
                    let content_type = file.type_();
                    self.common.call_backend(
                        ctx,
                        async move {
                            let file_bytes =
                                wasm_bindgen_futures::JsFuture::from(file.array_buffer())
                                    .await
                                    .map_err(|_| anyhow!("Could not read logo file"))?;
                            let array: js_sys::Uint8Array = js_sys::Uint8Array::new(&file_bytes);
                            let mut bytes = vec![0u8; array.length() as usize];
                            array.copy_to(&mut bytes);
                            // Upload the file first.
                            let upload_result =
                                HostService::upload_logo(bytes, file_name, content_type).await?;
                            // Then save the remaining branding fields.
                            let combined = BrandingOptions {
                                logo_file_has_been_uploaded: true,
                                logo_url: upload_result.logo_url,
                                ..branding_payload
                            };
                            HostService::update_settings(combined).await
                        },
                        AdminSettingsFormMessage::SettingsSaved,
                    );
                } else {
                    self.common.call_backend(
                        ctx,
                        HostService::update_settings(branding_payload),
                        AdminSettingsFormMessage::SettingsSaved,
                    );
                }
                Ok(true)
            }
            AdminSettingsFormMessage::SettingsSaved(Ok(options)) => {
                self.is_saving = false;
                self.success_message = Some("Branding settings saved successfully.".to_string());
                let branding = options.branding;
                self.form_model.application_name = branding.app_name;
                self.form_model.accent_color_hex = branding.accent_color.unwrap_or_default();
                self.form_model.logo_url = branding.logo_url.unwrap_or_default();
                self.form_model.logo_file_has_been_uploaded = branding.logo_file_has_been_uploaded;
                self.form_model.default_theme = branding.default_theme;
                self.form_model.pending_logo_file = None;
                // Reload the page so the banner picks up the new settings.
                if let Some(window) = web_sys::window() {
                    let _ = window.location().reload();
                }
                Ok(true)
            }
            AdminSettingsFormMessage::SettingsSaved(Err(error_message)) => {
                self.is_saving = false;
                self.common.error = Some(error_message);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for AdminSettingsForm {
    type Message = AdminSettingsFormMessage;
    type Properties = AdminSettingsFormProps;

    fn create(ctx: &Context<Self>) -> Self {
        let mut form = AdminSettingsForm {
            common: CommonComponentParts::<Self>::create(),
            form_model: SettingsFormModel::default(),
            is_saving: false,
            success_message: None,
        };
        form.common.call_backend(
            ctx,
            HostService::get_settings(),
            AdminSettingsFormMessage::SettingsFetched,
        );
        form
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let theme_selected = |mode: ThemeMode| -> bool { self.form_model.default_theme == mode };
        let is_disabled = self.is_saving;
        html! {
            <div>
                <h1 class="h3 mb-4">{"Branding settings"}</h1>

                {if let Some(message) = &self.success_message {
                    html! { <div class="alert alert-success">{message}</div> }
                } else {
                    html! {}
                }}

                {if let Some(error_message) = &self.common.error {
                    html! { <div class="alert alert-danger">{error_message.to_string()}</div> }
                } else {
                    html! {}
                }}

                <div class="app-panel">
                    <div class="mb-3">
                        <label for="settings-app-name" class="form-label">{"Application name"}</label>
                        <input
                            type="text"
                            id="settings-app-name"
                            class="form-control"
                            value={self.form_model.application_name.clone()}
                            disabled={is_disabled}
                            onchange={link.callback(|event: Event| {
                                let value = event.target_unchecked_into::<HtmlInputElement>().value();
                                AdminSettingsFormMessage::UpdateApplicationName(value)
                            })}
                        />
                        <div class="form-text">{"Shown in the browser tab and the top-left corner of every page."}</div>
                    </div>

                    <div class="mb-3">
                        <label for="settings-accent-color" class="form-label">{"Accent color"}</label>
                        <div class="d-flex gap-2">
                            <input
                                type="color"
                                id="settings-accent-color-picker"
                                class="form-control form-control-color"
                                value={self.form_model.accent_color_hex.clone()}
                                disabled={is_disabled}
                                onchange={link.callback(|event: Event| {
                                    let value = event.target_unchecked_into::<HtmlInputElement>().value();
                                    AdminSettingsFormMessage::UpdateAccentColor(value)
                                })}
                            />
                            <input
                                type="text"
                                id="settings-accent-color"
                                class="form-control"
                                placeholder="#4f46e5"
                                value={self.form_model.accent_color_hex.clone()}
                                disabled={is_disabled}
                                onchange={link.callback(|event: Event| {
                                    let value = event.target_unchecked_into::<HtmlInputElement>().value();
                                    AdminSettingsFormMessage::UpdateAccentColor(value)
                                })}
                            />
                        </div>
                        <div class="form-text">{"Primary colour used for buttons, links, and highlights. Leave empty to use the default indigo."}</div>
                    </div>

                    <div class="mb-3">
                        <label for="settings-default-theme" class="form-label">{"Default theme"}</label>
                        <select
                            id="settings-default-theme"
                            class="form-select"
                            disabled={is_disabled}
                            onchange={link.callback(|event: Event| {
                                let value = event.target_unchecked_into::<HtmlInputElement>().value();
                                AdminSettingsFormMessage::UpdateDefaultTheme(value)
                            })}
                        >
                            <option value="auto" selected={theme_selected(ThemeMode::Auto)}>{"Auto (follows system preference)"}</option>
                            <option value="light" selected={theme_selected(ThemeMode::Light)}>{"Light"}</option>
                            <option value="dark" selected={theme_selected(ThemeMode::Dark)}>{"Dark"}</option>
                        </select>
                        <div class="form-text">{"Applied only for visitors who have not picked a theme themselves."}</div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">{"Logo"}</label>
                        {if self.form_model.logo_file_has_been_uploaded {
                            html! {
                                <div class="mb-2">
                                    <img src="/branding/logo" alt="Current logo" style="max-height: 64px;" />
                                    <button
                                        type="button"
                                        class="btn btn-outline-danger btn-sm ms-2"
                                        disabled={is_disabled}
                                        onclick={link.callback(|_| AdminSettingsFormMessage::RemoveLogo)}
                                    >
                                        {"Remove uploaded logo"}
                                    </button>
                                </div>
                            }
                        } else {
                            html! {}
                        }}

                        <input
                            type="file"
                            id="settings-logo-file"
                            class="form-control mb-2"
                            accept="image/png,image/jpeg,image/webp,image/svg+xml"
                            disabled={is_disabled}
                            onchange={link.callback(|event: Event| {
                                let input = event.target_unchecked_into::<HtmlInputElement>();
                                let files = input.files();
                                let selected_file = files.and_then(|file_list| file_list.get(0));
                                AdminSettingsFormMessage::FileSelected(selected_file)
                            })}
                        />

                        <label for="settings-logo-url" class="form-label mt-2">{"Or provide a logo URL instead"}</label>
                        <input
                            type="url"
                            id="settings-logo-url"
                            class="form-control"
                            placeholder="https://example.com/logo.png"
                            value={self.form_model.logo_url.clone()}
                            disabled={is_disabled}
                            onchange={link.callback(|event: Event| {
                                let value = event.target_unchecked_into::<HtmlInputElement>().value();
                                AdminSettingsFormMessage::UpdateLogoUrl(value)
                            })}
                        />
                        <div class="form-text">{"If both an uploaded file and a URL are set, the uploaded file takes priority."}</div>
                    </div>

                    <button
                        type="button"
                        class="btn btn-primary"
                        disabled={is_disabled}
                        onclick={link.callback(|_| AdminSettingsFormMessage::SaveSettings)}
                    >
                        {if self.is_saving {
                            html! { <><span class="spinner-border spinner-border-sm me-2"></span>{"Saving..."}</> }
                        } else {
                            html! { <><i class="bi-check-circle me-2"></i>{"Save settings"}</> }
                        }}
                    </button>
                </div>
            </div>
        }
    }
}
