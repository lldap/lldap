use crate::{
    domain::sql_tables::{DbQueryBuilder, Pool},
    infra::jwt_sql_tables::{JwtRefreshStorage, JwtStorage},
};
use actix::prelude::*;
use chrono::Local;
use cron::Schedule;
use sea_query::{Expr, Query};
use std::{str::FromStr, time::Duration};

// Define actor
pub struct Scheduler {
    schedule: Schedule,
    sql_pool: Pool,
}

// Provide Actor implementation for our actor
impl Actor for Scheduler {
    type Context = Context<Self>;

    fn started(&mut self, context: &mut Context<Self>) {
        log::info!("DB Cleanup Cron started");

        context.run_later(self.duration_until_next(), move |this, ctx| {
            this.schedule_task(ctx)
        });
    }

    fn stopped(&mut self, _ctx: &mut Context<Self>) {
        log::info!("DB Cleanup stopped");
    }
}

impl Scheduler {
    pub fn new(cron_expression: &str, sql_pool: Pool) -> Self {
        let schedule = Schedule::from_str(cron_expression).unwrap();
        Self { schedule, sql_pool }
    }

    fn schedule_task(&self, ctx: &mut Context<Self>) {
        log::info!("Cleaning DB");
        let future = actix::fut::wrap_future::<_, Self>(Self::cleanup_db(self.sql_pool.clone()));
        ctx.spawn(future);

        ctx.run_later(self.duration_until_next(), move |this, ctx| {
            this.schedule_task(ctx)
        });
    }

    async fn cleanup_db(sql_pool: Pool) {
        if let Err(e) = sqlx::query(
            &Query::delete()
                .from_table(JwtRefreshStorage::Table)
                .and_where(Expr::col(JwtRefreshStorage::ExpiryDate).lt(Local::now().naive_utc()))
                .to_string(DbQueryBuilder {}),
        )
        .execute(&sql_pool)
        .await
        {
            log::error!("DB cleanup error: {}", e);
        };
        if let Err(e) = sqlx::query(
            &Query::delete()
                .from_table(JwtStorage::Table)
                .and_where(Expr::col(JwtStorage::ExpiryDate).lt(Local::now().naive_utc()))
                .to_string(DbQueryBuilder {}),
        )
        .execute(&sql_pool)
        .await
        {
            log::error!("DB cleanup error: {}", e);
        };
        log::info!("DB cleaned!");
    }

    fn duration_until_next(&self) -> Duration {
        let now = Local::now();
        let next = self.schedule.upcoming(Local).next().unwrap();
        let duration_until = next.signed_duration_since(now);
        duration_until.to_std().unwrap()
    }
}
