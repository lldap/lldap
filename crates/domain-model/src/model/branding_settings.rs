//! SeaORM entity for the `branding_settings` table.
//! Stores server-side branding configuration as a singleton row (id = 1).
//! The admin can update these values at runtime via PUT /settings without
//! restarting the server.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single-row table that holds the operator-configurable branding for the
/// web UI. The row with `id = 1` is created automatically by the v12 migration
/// and is never deleted. All columns except `id` can be updated at runtime.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "branding_settings")]
pub struct Model {
    /// Always 1 (singleton guard enforced by a CHECK constraint).
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,

    /// The title shown in the browser tab and the header of every page.
    pub app_name: String,

    /// An optional CSS colour (hex / rgb() / hsl() / named) used as the
    /// primary accent across the UI. When `None` falls back to the
    /// stylesheet default.
    pub accent_color: Option<String>,

    /// An optional URL pointing to an externally hosted logo image.
    /// Ignored when `logo_file_has_been_uploaded` is `true`.
    pub logo_url: Option<String>,

    /// When `true` the frontend renders the uploaded file served from
    /// `/branding/logo` instead of using `logo_url` or the default icon.
    pub logo_file_has_been_uploaded: bool,

    /// The initial colour scheme for visitors who have not explicitly
    /// picked one. One of `"light"`, `"dark"`, or `"auto"`.
    pub default_theme: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
