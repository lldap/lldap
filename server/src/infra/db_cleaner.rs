use crate::domain::{
    model::{self, JwtRefreshStorageColumn, JwtStorageColumn, PasswordResetTokensColumn},
    sql_tables::DbConnection,
};
use actix::prelude::{Actor, AsyncContext, Context};
use cron::Schedule;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{str::FromStr, time::Duration};
use tracing::{error, info, instrument};

// Define actor
pub struct Scheduler {
    schedule: Schedule,
    sql_pool: DbConnection,
}

// Provide Actor implementation for our actor
impl Actor for Scheduler {
    type Context = Context<Self>;

    fn started(&mut self, context: &mut Context<Self>) {
        info!("DB Cleanup Cron started");

        context.run_later(self.duration_until_next(), move |this, ctx| {
            this.schedule_task(ctx)
        });
    }

    fn stopped(&mut self, _ctx: &mut Context<Self>) {
        info!("DB Cleanup stopped");
    }
}

impl Scheduler {
    pub fn new(cron_expression: &str, sql_pool: DbConnection) -> Self {
        let schedule = Schedule::from_str(cron_expression).unwrap();
        Self { schedule, sql_pool }
    }

    fn schedule_task(&self, ctx: &mut Context<Self>) {
        let future = actix::fut::wrap_future::<_, Self>(Self::cleanup_db(self.sql_pool.clone()));
        ctx.spawn(future);

        ctx.run_later(self.duration_until_next(), move |this, ctx| {
            this.schedule_task(ctx)
        });
    }

    #[instrument(skip_all)]
    async fn cleanup_db(sql_pool: DbConnection) {
        info!("Cleaning DB");
        if let Err(e) = model::JwtRefreshStorage::delete_many()
            .filter(JwtRefreshStorageColumn::ExpiryDate.lt(chrono::Utc::now().naive_utc()))
            .exec(&sql_pool)
            .await
        {
            error!("DB error while cleaning up JWT refresh tokens: {}", e);
        }
        if let Err(e) = model::JwtStorage::delete_many()
            .filter(JwtStorageColumn::ExpiryDate.lt(chrono::Utc::now().naive_utc()))
            .exec(&sql_pool)
            .await
        {
            error!("DB error while cleaning up JWT storage: {}", e);
        };
        if let Err(e) = model::PasswordResetTokens::delete_many()
            .filter(PasswordResetTokensColumn::ExpiryDate.lt(chrono::Utc::now().naive_utc()))
            .exec(&sql_pool)
            .await
        {
            error!("DB error while cleaning up password reset tokens: {}", e);
        };
        info!("DB cleaned!");
    }

    fn duration_until_next(&self) -> Duration {
        let now = chrono::Utc::now();
        let next = self.schedule.upcoming(chrono::Utc).next().unwrap();
        let duration_until = next.signed_duration_since(now);
        duration_until.to_std().unwrap()
    }
}
