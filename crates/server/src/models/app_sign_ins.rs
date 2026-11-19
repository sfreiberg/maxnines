//! Apps signed in through the browser, and the tokens they hold.

use anyhow::{Context, Result, ensure};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait,
};
use serde::Serialize;
use serde_json::json;

use super::audit::record_change;
use super::users::enabled_user;
use super::{Database, User, app_sign_in, owner_emails, user};
use crate::app_sign_ins::{
    ACCESS_LIFETIME, ACCESS_PREFIX, REFRESH_GRACE, REFRESH_LIFETIME, REFRESH_PREFIX, app_name,
    client, new_secret, secret_hash,
};
use crate::audit::{Kind, Record, Snapshot};
use crate::roles::Role;
use crate::times::Timestamp;

/// An app someone signed in, as the pages and the API show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppSignIn {
    pub id: i64,
    pub user_id: i64,
    /// Who it acts as.
    pub owner: String,
    pub client_id: String,
    /// The app's name, such as "MaxNines command line".
    pub app: String,
    /// What the app calls the computer it's on, if it said.
    pub device: Option<String>,
    /// The most it may do. It never does more than its owner can now.
    pub role: Role,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    /// The address it was last used from.
    pub last_address: Option<String>,
    /// What an untrusted proxy there said it was passing on, so unconfirmed.
    pub last_forwarded_for: Option<String>,
    /// When it stops working unless it's used before then.
    pub expires_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

impl AppSignIn {
    fn from_row(row: app_sign_in::Model, owner: String) -> Self {
        let app = app_name(&row.client_id);
        Self {
            id: row.id,
            user_id: row.user_id,
            owner,
            app,
            role: Role::parse(&row.role).unwrap_or(Role::Viewer),
            client_id: row.client_id,
            device: row.device,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            last_address: row.last_address,
            last_forwarded_for: row.last_forwarded_for,
            expires_at: row.refresh_expires_at,
            revoked_at: row.revoked_at,
        }
    }

    pub fn is_active(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    /// What it's called where it's listed, and in the audit log.
    pub fn title(&self) -> String {
        match &self.device {
            Some(device) => format!("{} on {device}", self.app),
            None => self.app.clone(),
        }
    }
}

/// What an app is given: the only copies there'll be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTokens {
    pub access_token: String,
    pub refresh_token: String,
}

/// How swapping a refresh token went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refreshed {
    Issued(Box<AppSignIn>, AppTokens),
    /// Not a token that works: wrong, expired, revoked, or its owner is disabled.
    Refused,
    /// One already swapped was used again, so it's been copied: the sign in is revoked.
    Reused,
}

fn snapshot(row: &app_sign_in::Model, owner: &str) -> Snapshot {
    let app = app_name(&row.client_id);
    let fields = json!({
        "app": app,
        "device": row.device,
        "owner": owner,
        "role": row.role,
        "revoked": row.revoked_at.is_some(),
    });
    let name = match &row.device {
        Some(device) => format!("{app} on {device}"),
        None => app.to_string(),
    };
    Snapshot::new(name, fields)
}

/// How long one that's been revoked or has run out stays listed before it's deleted.
/// The audit log keeps what happened to it.
const KEPT_AFTER_ENDING: chrono::TimeDelta = chrono::TimeDelta::days(90);

/// The email address of the user with this ID, or nothing if they've gone.
async fn owner_email<C: ConnectionTrait>(connection: &C, user_id: i64) -> Result<String> {
    let row = user::Entity::find_by_id(user_id)
        .one(connection)
        .await
        .context("loading a signed in app's owner")?;
    Ok(row.map(|row| row.email).unwrap_or_default())
}

fn new_tokens() -> Result<AppTokens> {
    Ok(AppTokens {
        access_token: new_secret(ACCESS_PREFIX)?,
        refresh_token: new_secret(REFRESH_PREFIX)?,
    })
}

impl Database {
    /// Signs in an app as `user_id` with at most `role`, giving back its tokens. The
    /// owner has to be someone who can sign in, and the app can't do more than they can.
    pub async fn create_app_sign_in(
        &self,
        user_id: i64,
        client_id: &str,
        device: Option<&str>,
        role: Role,
        now: Timestamp,
    ) -> Result<(AppSignIn, AppTokens)> {
        ensure!(
            client(client_id).is_some(),
            "there's no app called {client_id}"
        );
        let tokens = new_tokens()?;
        // Ones that ended long ago go, so the list doesn't grow with every sign in.
        let ended = now - KEPT_AFTER_ENDING;
        app_sign_in::Entity::delete_many()
            .filter(
                sea_orm::Condition::any()
                    .add(app_sign_in::Column::RevokedAt.lt(ended))
                    .add(app_sign_in::Column::RefreshExpiresAt.lt(ended)),
            )
            .exec(&self.connection)
            .await
            .context("clearing old signed in apps")?;
        let transaction = self.connection.begin().await.context("signing in an app")?;
        let owner = enabled_user(&transaction, user_id)
            .await?
            .context("an app has to act as a user who isn't disabled")?;
        ensure!(role <= owner.role, "an app can't do more than its owner");
        let row = app_sign_in::ActiveModel {
            user_id: Set(user_id),
            client_id: Set(client_id.to_string()),
            device: Set(device.map(str::to_string)),
            role: Set(role.as_str().to_string()),
            access_hash: Set(secret_hash(&tokens.access_token)),
            access_expires_at: Set(now + ACCESS_LIFETIME),
            refresh_hash: Set(secret_hash(&tokens.refresh_token)),
            refresh_expires_at: Set(now + REFRESH_LIFETIME),
            created_at: Set(now),
            last_used_at: Set(Some(now)),
            last_address: Set(crate::audit::source().map(|address| address.to_string())),
            last_forwarded_for: Set(
                crate::audit::forwarded_for().map(|address| address.to_string())
            ),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .context("saving a signed in app")?;
        let after = snapshot(&row, &owner.email);
        record_change(
            &transaction,
            Kind::AppSignIn,
            row.id,
            None,
            Some(&after),
            None,
        )
        .await?;
        transaction.commit().await.context("signing in an app")?;
        Ok((AppSignIn::from_row(row, owner.email), tokens))
    }

    /// The sign in an access token belongs to and who it acts as, if it still works,
    /// noting that it's been used. It acts as its owner with whichever of their roles
    /// is less, and not at all while they're disabled.
    pub async fn accept_app_token(
        &self,
        access_token: &str,
        now: Timestamp,
    ) -> Result<Option<(AppSignIn, User)>> {
        let row = app_sign_in::Entity::find()
            .filter(app_sign_in::Column::AccessHash.eq(secret_hash(access_token)))
            .filter(app_sign_in::Column::RevokedAt.is_null())
            .one(&self.connection)
            .await
            .context("checking an app's token")?;
        let Some(row) = row.filter(|row| now < row.access_expires_at) else {
            return Ok(None);
        };
        let Some(mut owner) = enabled_user(&self.connection, row.user_id).await? else {
            return Ok(None);
        };
        let role = Role::parse(&row.role).unwrap_or(Role::Viewer);
        owner.role = owner.role.min(role);
        let last = super::UsedFrom {
            address: row.last_address.clone(),
            forwarded_for: row.last_forwarded_for.clone(),
        };
        let row = if let Some((used, from)) = super::noted_use(row.last_used_at, &last, now) {
            let mut row: app_sign_in::ActiveModel = row.into();
            row.last_used_at = Set(Some(used));
            row.last_address = Set(from.address);
            row.last_forwarded_for = Set(from.forwarded_for);
            row.update(&self.connection)
                .await
                .context("noting an app's use")?
        } else {
            row
        };
        Ok(Some((AppSignIn::from_row(row, owner.email.clone()), owner)))
    }

    /// Swaps a refresh token for new tokens. The old one stops working, apart from a
    /// minute's grace from when it was swapped, in case the answer was lost; used after
    /// that, it's been copied, and the whole sign in is revoked.
    pub async fn refresh_app_sign_in(
        &self,
        refresh_token: &str,
        client_id: &str,
        now: Timestamp,
    ) -> Result<Refreshed> {
        // Another refresh may swap the same token at the same moment. Whichever comes
        // second finds it just swapped, and goes again as one inside the grace.
        for _ in 0..3 {
            if let Some(refreshed) = self.try_refresh(refresh_token, client_id, now).await? {
                return Ok(refreshed);
            }
        }
        Ok(Refreshed::Refused)
    }

    /// One go at a refresh, or nothing if another changed the sign in first.
    async fn try_refresh(
        &self,
        refresh_token: &str,
        client_id: &str,
        now: Timestamp,
    ) -> Result<Option<Refreshed>> {
        let hash = secret_hash(refresh_token);
        let transaction = self.connection.begin().await.context("refreshing an app")?;
        let current = app_sign_in::Entity::find()
            .filter(app_sign_in::Column::RefreshHash.eq(hash.as_str()))
            .one(&transaction)
            .await
            .context("checking a refresh token")?;
        let (row, in_grace) = match current {
            Some(row) => (row, false),
            None => {
                let previous = app_sign_in::Entity::find()
                    .filter(app_sign_in::Column::PreviousRefreshHash.eq(hash.as_str()))
                    .one(&transaction)
                    .await
                    .context("checking a refresh token")?;
                let Some(row) = previous else {
                    return Ok(Some(Refreshed::Refused));
                };
                let in_grace = row
                    .rotated_at
                    .is_some_and(|rotated| now - rotated < REFRESH_GRACE);
                if !in_grace {
                    if row.revoked_at.is_none() {
                        revoke_row(&transaction, row, now).await?;
                        transaction.commit().await.context("revoking an app")?;
                        return Ok(Some(Refreshed::Reused));
                    }
                    return Ok(Some(Refreshed::Refused));
                }
                (row, true)
            }
        };
        let usable =
            row.client_id == client_id && row.revoked_at.is_none() && now < row.refresh_expires_at;
        if !usable {
            return Ok(Some(Refreshed::Refused));
        }
        let Some(owner) = enabled_user(&transaction, row.user_id).await? else {
            return Ok(Some(Refreshed::Refused));
        };
        let tokens = new_tokens()?;
        let mut changes = app_sign_in::ActiveModel {
            access_hash: Set(secret_hash(&tokens.access_token)),
            access_expires_at: Set(now + ACCESS_LIFETIME),
            refresh_hash: Set(secret_hash(&tokens.refresh_token)),
            refresh_expires_at: Set(now + REFRESH_LIFETIME),
            last_used_at: Set(Some(now)),
            ..Default::default()
        };
        // Within the grace, the token being swapped is still the one swapped before,
        // and its minute still counts from then, so using it again can't stretch it.
        if !in_grace {
            changes.previous_refresh_hash = Set(Some(hash));
            changes.rotated_at = Set(Some(now));
        }
        // Only if nothing has swapped it since it was read.
        let swapped = app_sign_in::Entity::update_many()
            .set(changes)
            .filter(app_sign_in::Column::Id.eq(row.id))
            .filter(app_sign_in::Column::RefreshHash.eq(row.refresh_hash.as_str()))
            .filter(app_sign_in::Column::RevokedAt.is_null())
            .exec(&transaction)
            .await
            .context("refreshing an app")?;
        if swapped.rows_affected == 0 {
            return Ok(None);
        }
        let row = app_sign_in::Entity::find_by_id(row.id)
            .one(&transaction)
            .await
            .context("refreshing an app")?
            .context("a refreshed app disappeared")?;
        transaction.commit().await.context("refreshing an app")?;
        Ok(Some(Refreshed::Issued(
            Box::new(AppSignIn::from_row(row, owner.email)),
            tokens,
        )))
    }

    /// The apps signed in, newest first, including revoked and expired ones for a
    /// while: everyone's, or only `user_id`'s.
    pub async fn list_app_sign_ins(&self, user_id: Option<i64>) -> Result<Vec<AppSignIn>> {
        let mut query = app_sign_in::Entity::find().order_by_desc(app_sign_in::Column::Id);
        if let Some(user_id) = user_id {
            query = query.filter(app_sign_in::Column::UserId.eq(user_id));
        }
        let rows = query
            .all(&self.connection)
            .await
            .context("loading signed in apps")?;
        let owners = owner_emails(&self.connection).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let owner = owners.get(&row.user_id).cloned().unwrap_or_default();
                AppSignIn::from_row(row, owner)
            })
            .collect())
    }

    /// One app sign in, if there is one with that ID.
    pub async fn get_app_sign_in(&self, id: i64) -> Result<Option<AppSignIn>> {
        let Some(row) = app_sign_in::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading a signed in app")?
        else {
            return Ok(None);
        };
        let owner = owner_email(&self.connection, row.user_id).await?;
        Ok(Some(AppSignIn::from_row(row, owner)))
    }

    /// How many apps are signed in and working now: everyone's, or only `user_id`'s.
    pub async fn count_active_app_sign_ins(
        &self,
        user_id: Option<i64>,
        now: Timestamp,
    ) -> Result<u64> {
        let mut query = app_sign_in::Entity::find()
            .filter(app_sign_in::Column::RevokedAt.is_null())
            .filter(app_sign_in::Column::RefreshExpiresAt.gt(now));
        if let Some(user_id) = user_id {
            query = query.filter(app_sign_in::Column::UserId.eq(user_id));
        }
        query
            .count(&self.connection)
            .await
            .context("counting signed in apps")
    }

    /// Signs an app out. Returns false if there's no such sign in.
    pub async fn revoke_app_sign_in(&self, id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("revoking an app")?;
        let Some(row) = app_sign_in::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("loading a signed in app")?
        else {
            return Ok(false);
        };
        if row.revoked_at.is_none() {
            revoke_row(&transaction, row, now).await?;
            transaction.commit().await.context("revoking an app")?;
        }
        Ok(true)
    }

    /// Signs out whichever app holds this token, access or refresh, as an app does when
    /// someone signs it out. A token that's nobody's is ignored.
    pub async fn revoke_app_token(
        &self,
        token: &str,
        client_id: &str,
        now: Timestamp,
    ) -> Result<()> {
        let hash = secret_hash(token);
        let row = app_sign_in::Entity::find()
            .filter(
                sea_orm::Condition::any()
                    .add(app_sign_in::Column::AccessHash.eq(hash.as_str()))
                    .add(app_sign_in::Column::RefreshHash.eq(hash.as_str())),
            )
            .one(&self.connection)
            .await
            .context("checking an app's token")?;
        match row {
            Some(row) if row.client_id == client_id => {
                self.revoke_app_sign_in(row.id, now).await.map(|_| ())
            }
            _ => Ok(()),
        }
    }
}

async fn revoke_row<C: ConnectionTrait>(
    connection: &C,
    row: app_sign_in::Model,
    now: Timestamp,
) -> Result<()> {
    let owner = owner_email(connection, row.user_id).await?;
    let before = snapshot(&row, &owner);
    let mut active: app_sign_in::ActiveModel = row.into();
    active.revoked_at = Set(Some(now));
    let row = active.update(connection).await.context("revoking an app")?;
    let after = snapshot(&row, &owner);
    record_change(
        connection,
        Kind::AppSignIn,
        row.id,
        Some(&before),
        Some(&after),
        None,
    )
    .await
}

/// What the audit log says of the apps a user signed in when the user is deleted,
/// which they go with.
pub(super) async fn deleted_with_user<C: ConnectionTrait>(
    connection: &C,
    user_id: i64,
    email: &str,
) -> Result<Vec<Record>> {
    let rows = app_sign_in::Entity::find()
        .filter(app_sign_in::Column::UserId.eq(user_id))
        .all(connection)
        .await
        .context("loading their signed in apps")?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let before = snapshot(row, email);
            Record::of_change(Kind::AppSignIn, row.id, Some(&before), None, None)
        })
        .collect())
}
