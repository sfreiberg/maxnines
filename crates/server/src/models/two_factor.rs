//! Two-factor sign-in: each person's authenticator secret and recovery codes, the
//! moment between a right password and a right code, and whether everyone has to
//! use it.

use anyhow::{Context, Result};
use maxnines_protocol::auth::new_nonce;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter, Set, TransactionTrait,
};
use serde_json::json;

use super::audit::record_change;
use super::users::{load, record_user, token_hash};
use super::{Database, User, recovery_code, server_setting, sign_in_challenge, user};
use crate::audit::{Kind, Snapshot};
use crate::two_factor::{matching_step, new_recovery_codes, new_secret, normalise_recovery_code};

/// How long someone has to type their code after their password.
pub const CHALLENGE_LIFETIME_MS: i64 = 5 * 60 * 1000;
const REQUIRE_TWO_FACTOR: &str = "require_two_factor";

fn code_hash(code: &str) -> String {
    token_hash(&normalise_recovery_code(code))
}

/// Replaces someone's recovery codes, and gives back the only copy of the new ones.
async fn replace_recovery_codes<C: ConnectionTrait>(
    connection: &C,
    id: i64,
) -> Result<Vec<String>> {
    recovery_code::Entity::delete_many()
        .filter(recovery_code::Column::UserId.eq(id))
        .exec(connection)
        .await
        .context("clearing recovery codes")?;
    let codes = new_recovery_codes()?;
    let rows = codes.iter().map(|code| recovery_code::ActiveModel {
        user_id: Set(id),
        code_hash: Set(code_hash(code)),
        used_ms: Set(None),
        ..Default::default()
    });
    recovery_code::Entity::insert_many(rows)
        .exec_without_returning(connection)
        .await
        .context("saving recovery codes")?;
    Ok(codes)
}

/// Removes what two-factor keeps for someone being deleted.
pub(super) async fn forget<C: ConnectionTrait>(connection: &C, id: i64) -> Result<()> {
    recovery_code::Entity::delete_many()
        .filter(recovery_code::Column::UserId.eq(id))
        .exec(connection)
        .await
        .context("clearing recovery codes")?;
    sign_in_challenge::Entity::delete_many()
        .filter(sign_in_challenge::Column::UserId.eq(id))
        .exec(connection)
        .await
        .context("clearing sign in challenges")?;
    Ok(())
}

fn secs(now_ms: i64) -> u64 {
    u64::try_from(now_ms / 1000).unwrap_or_default()
}

impl Database {
    /// Starts setting up two-factor, and gives the secret for their app. Nothing
    /// changes about signing in until [`Self::confirm_two_factor`]. Returns `None`
    /// if they already have it on, or aren't a user.
    pub async fn start_two_factor(&self, id: i64) -> Result<Option<String>> {
        let secret = new_secret();
        let updated = user::Entity::update_many()
            .col_expr(user::Column::TotpSecret, Expr::value(secret.clone()))
            .filter(user::Column::Id.eq(id))
            .filter(user::Column::TotpEnabled.eq(false))
            .exec(&self.connection)
            .await
            .context("saving a two-factor secret")?;
        Ok((updated.rows_affected == 1).then_some(secret))
    }

    /// The secret someone is part way through setting up.
    pub async fn pending_two_factor_secret(&self, id: i64) -> Result<Option<String>> {
        let row = load(&self.connection, id).await?;
        Ok(row
            .filter(|row| !row.totp_enabled)
            .and_then(|row| row.totp_secret))
    }

    /// Turns two-factor on once a code from their app proves it's set up, and gives
    /// back their recovery codes, the only time they're seen. Returns `None` for a
    /// wrong code, or if there's nothing being set up.
    pub async fn confirm_two_factor(
        &self,
        id: i64,
        code: &str,
        now_ms: i64,
    ) -> Result<Option<Vec<String>>> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let Some(before) = load(&transaction, id)
            .await?
            .filter(|row| !row.totp_enabled)
        else {
            return Ok(None);
        };
        let Some(secret) = &before.totp_secret else {
            return Ok(None);
        };
        let Some(step) = matching_step(secret, &before.email, code, secs(now_ms))? else {
            return Ok(None);
        };
        let mut row: user::ActiveModel = before.clone().into();
        row.totp_enabled = Set(true);
        row.totp_last_step = Set(i64::try_from(step).ok());
        row.update(&transaction)
            .await
            .context("turning on two-factor")?;
        let codes = replace_recovery_codes(&transaction, id).await?;
        record_user(&transaction, id, Some(&before), None).await?;
        transaction
            .commit()
            .await
            .context("turning on two-factor")?;
        Ok(Some(codes))
    }

    /// Whether this is a code that signs them in: one from their app, for a step not
    /// used before, or a recovery code not used before. Either is used up by this.
    pub async fn accept_two_factor_code(&self, id: i64, code: &str, now_ms: i64) -> Result<bool> {
        let Some(row) = load(&self.connection, id)
            .await?
            .filter(|row| row.totp_enabled)
        else {
            return Ok(false);
        };
        let secret = row.totp_secret.as_deref().unwrap_or_default();
        if let Some(step) = matching_step(secret, &row.email, code, secs(now_ms))? {
            let step = i64::try_from(step).context("an impossible time")?;
            // One update, so the same code sent twice at once only works once.
            let unused = Condition::any()
                .add(user::Column::TotpLastStep.is_null())
                .add(user::Column::TotpLastStep.lt(step));
            let updated = user::Entity::update_many()
                .col_expr(user::Column::TotpLastStep, Expr::value(step))
                .filter(user::Column::Id.eq(id))
                .filter(unused)
                .exec(&self.connection)
                .await
                .context("noting a code's use")?;
            return Ok(updated.rows_affected == 1);
        }
        let used = recovery_code::Entity::update_many()
            .col_expr(recovery_code::Column::UsedMs, Expr::value(now_ms))
            .filter(recovery_code::Column::UserId.eq(id))
            .filter(recovery_code::Column::CodeHash.eq(code_hash(code)))
            .filter(recovery_code::Column::UsedMs.is_null())
            .exec(&self.connection)
            .await
            .context("using a recovery code")?;
        Ok(used.rows_affected == 1)
    }

    /// How many recovery codes someone has left.
    pub async fn recovery_codes_left(&self, id: i64) -> Result<u64> {
        recovery_code::Entity::find()
            .filter(recovery_code::Column::UserId.eq(id))
            .filter(recovery_code::Column::UsedMs.is_null())
            .count(&self.connection)
            .await
            .context("counting recovery codes")
    }

    /// New recovery codes in place of the old, for someone with two-factor on.
    pub async fn new_recovery_codes(&self, id: i64) -> Result<Option<Vec<String>>> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        if load(&transaction, id)
            .await?
            .is_none_or(|row| !row.totp_enabled)
        {
            return Ok(None);
        }
        let codes = replace_recovery_codes(&transaction, id).await?;
        transaction
            .commit()
            .await
            .context("saving recovery codes")?;
        Ok(Some(codes))
    }

    /// Turns two-factor off and forgets the secret and recovery codes, whether it
    /// was on or part way set up. Returns false if they aren't a user.
    pub async fn turn_off_two_factor(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let Some(before) = load(&transaction, id).await? else {
            return Ok(false);
        };
        let mut row: user::ActiveModel = before.clone().into();
        row.totp_secret = Set(None);
        row.totp_enabled = Set(false);
        row.totp_last_step = Set(None);
        row.update(&transaction)
            .await
            .context("turning off two-factor")?;
        forget(&transaction, id).await?;
        record_user(&transaction, id, Some(&before), None).await?;
        transaction
            .commit()
            .await
            .context("turning off two-factor")?;
        Ok(true)
    }

    /// Remembers that someone gave the right password and still owes a code, and
    /// gives back the only copy of the token their browser keeps meanwhile.
    pub async fn start_sign_in_challenge(&self, user_id: i64, now_ms: i64) -> Result<String> {
        sign_in_challenge::Entity::delete_many()
            .filter(sign_in_challenge::Column::ExpiresMs.lte(now_ms))
            .exec(&self.connection)
            .await
            .context("clearing old sign in challenges")?;
        let token = new_nonce()?;
        sign_in_challenge::ActiveModel {
            user_id: Set(user_id),
            token_hash: Set(token_hash(&token)),
            expires_ms: Set(now_ms + CHALLENGE_LIFETIME_MS),
            ..Default::default()
        }
        .insert(&self.connection)
        .await
        .context("saving a sign in challenge")?;
        Ok(token)
    }

    /// Who owes a code for this token, if it still stands.
    pub async fn sign_in_challenge_user(&self, token: &str, now_ms: i64) -> Result<Option<User>> {
        let challenge = sign_in_challenge::Entity::find()
            .filter(sign_in_challenge::Column::TokenHash.eq(token_hash(token)))
            .filter(sign_in_challenge::Column::ExpiresMs.gt(now_ms))
            .one(&self.connection)
            .await
            .context("checking a sign in challenge")?;
        let Some(challenge) = challenge else {
            return Ok(None);
        };
        let row = load(&self.connection, challenge.user_id).await?;
        Ok(row.filter(|row| row.disabled_ms.is_none()).map(User::from))
    }

    pub async fn end_sign_in_challenge(&self, token: &str) -> Result<()> {
        sign_in_challenge::Entity::delete_many()
            .filter(sign_in_challenge::Column::TokenHash.eq(token_hash(token)))
            .exec(&self.connection)
            .await
            .context("ending a sign in challenge")?;
        Ok(())
    }

    /// Whether everyone has to set up two-factor before using the pages.
    pub async fn two_factor_required(&self) -> Result<bool> {
        let row = server_setting::Entity::find_by_id(REQUIRE_TWO_FACTOR)
            .one(&self.connection)
            .await
            .context("reading a setting")?;
        Ok(row.is_some_and(|row| row.value == "true"))
    }

    pub async fn require_two_factor(&self, required: bool) -> Result<()> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let before = server_setting::Entity::find_by_id(REQUIRE_TWO_FACTOR)
            .one(&transaction)
            .await
            .context("reading a setting")?
            .is_some_and(|row| row.value == "true");
        let row = server_setting::ActiveModel {
            name: Set(REQUIRE_TWO_FACTOR.to_string()),
            value: Set(required.to_string()),
        };
        let replace = OnConflict::column(server_setting::Column::Name)
            .update_column(server_setting::Column::Value)
            .to_owned();
        server_setting::Entity::insert(row)
            .on_conflict(replace)
            .exec_without_returning(&transaction)
            .await
            .context("saving a setting")?;
        let snapshot = |required: bool| {
            Snapshot::new(
                "Two-factor sign-in",
                json!({ "required_for_everyone": required }),
            )
        };
        let (before, after) = (snapshot(before), snapshot(required));
        record_change(
            &transaction,
            Kind::Setting,
            REQUIRE_TWO_FACTOR,
            Some(&before),
            Some(&after),
            None,
        )
        .await?;
        transaction.commit().await.context("saving a setting")
    }
}
