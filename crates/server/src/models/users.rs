//! The people who can sign in, and their sessions. Everyone is added by someone
//! already here, or from the server's command line. There's no way to sign up.
//!
//! However someone proves who they are, `start_session` is what signs them in, and
//! a password is optional. A way of signing in that doesn't use one, like single
//! sign-on, only has to find the user and call it.

use anyhow::{Context, Result, ensure};
use chrono_tz::Tz;
use lettre::Address;
use maxnines_protocol::auth::new_nonce;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait,
};
use serde::Serialize;
use serde_json::json;

use super::audit::{record, record_change};
use super::{Database, user, user_session};
use crate::audit::{Action, Actor, Kind, Record, Snapshot, Subject};
use crate::registration::hash_token;
use crate::times::{DEFAULT_TIME_ZONE, zone_named};

pub const SESSION_LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const SETUP_LINK_LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_EMAIL_LEN: usize = 254;
const MAX_NAME_LEN: usize = 100;
const MIN_PASSWORD_CHARS: usize = 12;
/// Hashing is slow on purpose, so this stops a huge password being used to waste time.
const MAX_PASSWORD_BYTES: usize = 1024;

pub const DEFAULT_THEME: &str = "carbon";
/// What a theme can be set to, with its name on the page. Each has colours in
/// themes.css, apart from `system`, which the browser turns into one that does.
pub const THEMES: [(&str, &str); 6] = [
    ("carbon", "Carbon"),
    ("midnight", "Midnight"),
    ("dusk", "Dusk"),
    ("paper", "Paper"),
    ("contrast", "High contrast"),
    ("system", "Match system"),
];

/// Someone who can sign in, without anything that would let you sign in as them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub theme: String,
    /// What the pages show times in, from the time zone database.
    pub time_zone: String,
    pub has_password: bool,
    pub created_ms: i64,
    pub last_sign_in_ms: Option<i64>,
    pub disabled_ms: Option<i64>,
}

impl From<user::Model> for User {
    fn from(row: user::Model) -> Self {
        Self {
            id: row.id,
            has_password: row.password_hash.is_some(),
            email: row.email,
            name: row.name,
            theme: row.theme,
            time_zone: row.time_zone,
            created_ms: row.created_ms,
            last_sign_in_ms: row.last_sign_in_ms,
            disabled_ms: row.disabled_ms,
        }
    }
}

impl User {
    /// The zone they read times in. Only real zones are saved, so UTC only stands in
    /// for one that a later version of the time zone database has dropped.
    pub fn zone(&self) -> Tz {
        zone_named(&self.time_zone).unwrap_or(DEFAULT_TIME_ZONE)
    }
}

/// What came of changing a user, for changes that can be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserChange {
    Done,
    NoSuchUser,
    /// It would leave nobody able to sign in.
    LastUser,
    /// Only disabled users can be deleted, so it always takes two steps.
    StillEnabled,
}

/// An address in the form it's kept, which is how two spellings of it match.
pub fn normalise_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// The address and name to use for a new user.
pub fn check_new_user(email: &str, name: &str) -> Result<(String, String)> {
    let email = normalise_email(email);
    ensure!(
        email.len() <= MAX_EMAIL_LEN && email.parse::<Address>().is_ok(),
        "Enter a valid email address."
    );
    let name = name.trim();
    ensure!(!name.is_empty(), "A user needs a name.");
    ensure!(
        name.len() <= MAX_NAME_LEN,
        "A name can be up to {MAX_NAME_LEN} characters."
    );
    Ok((email, name.to_string()))
}

/// Length is what makes a password strong, so that's all this asks for.
pub fn check_new_password(password: &str) -> Result<()> {
    ensure!(
        password.chars().count() >= MIN_PASSWORD_CHARS,
        "A password needs at least {MIN_PASSWORD_CHARS} characters."
    );
    ensure!(
        password.len() <= MAX_PASSWORD_BYTES,
        "That password is too long."
    );
    Ok(())
}

pub fn is_theme(theme: &str) -> bool {
    THEMES.iter().any(|(name, _)| *name == theme)
}

fn token_hash(token: &str) -> String {
    hex::encode(hash_token(token))
}

/// A user as the audit log compares them. The password is a secret, so only
/// whether it was set or changed is kept.
fn snapshot(row: &user::Model) -> Snapshot {
    let fields = json!({
        "email": row.email,
        "name": row.name,
        "theme": row.theme,
        "time_zone": row.time_zone,
        "password": row.password_hash,
        "disabled": row.disabled_ms.is_some(),
    });
    Snapshot::new(row.email.clone(), fields).with_secrets(&["password"])
}

fn as_actor(row: &user::Model) -> Actor {
    Actor::Person {
        id: row.id,
        email: row.email.clone(),
    }
}

async fn load<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Option<user::Model>> {
    user::Entity::find_by_id(id)
        .one(connection)
        .await
        .context("loading a user")
}

/// Records how a user changed from `before`, reading them as they are now.
async fn record_user<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&user::Model>,
    by: Option<Actor>,
) -> Result<()> {
    let after = load(connection, id).await?;
    let Some(entry) = Record::of_change(
        Kind::User,
        id,
        before.map(snapshot).as_ref(),
        after.as_ref().map(snapshot).as_ref(),
        None,
    ) else {
        return Ok(());
    };
    match by {
        Some(actor) => record(connection, entry.by(actor)).await,
        None => record(connection, entry).await,
    }
}

impl Database {
    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = user::Entity::find()
            .order_by_asc(user::Column::Email)
            .all(&self.connection)
            .await
            .context("loading users")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn user(&self, id: i64) -> Result<Option<User>> {
        let row = user::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading a user")?;
        Ok(row.map(Into::into))
    }

    pub async fn user_count(&self) -> Result<u64> {
        user::Entity::find()
            .count(&self.connection)
            .await
            .context("counting users")
    }

    /// Adds someone, and gives back the link token for setting their password.
    /// Returns `None` if the address is taken. Expects `check_new_user`'s results.
    pub async fn create_user(
        &self,
        email: &str,
        name: &str,
        now_ms: i64,
    ) -> Result<Option<(User, String)>> {
        let taken = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.connection)
            .await
            .context("checking a user's address")?;
        if taken.is_some() {
            return Ok(None);
        }
        let token = new_nonce()?;
        let transaction = self.connection.begin().await.context("starting a save")?;
        let row = user::ActiveModel {
            email: Set(email.to_string()),
            name: Set(name.to_string()),
            theme: Set(DEFAULT_THEME.to_string()),
            time_zone: Set(DEFAULT_TIME_ZONE.name().to_string()),
            setup_token_hash: Set(Some(token_hash(&token))),
            setup_expires_ms: Set(Some(now_ms + SETUP_LINK_LIFETIME_MS)),
            created_ms: Set(now_ms),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .context("saving a user")?;
        record_change(
            &transaction,
            Kind::User,
            row.id,
            None,
            Some(&snapshot(&row)),
            None,
        )
        .await?;
        transaction.commit().await.context("saving a user")?;
        Ok(Some((row.into(), token)))
    }

    /// Replaces a user's setup link with a new one, which is how a forgotten password
    /// is reset. Their current password works until the link is used.
    pub async fn new_setup_link(&self, id: i64, now_ms: i64) -> Result<Option<String>> {
        let Some(row) = user::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading a user")?
        else {
            return Ok(None);
        };
        let token = new_nonce()?;
        let subject = Subject::new(Kind::User, row.id, row.email.clone());
        let transaction = self.connection.begin().await.context("starting a save")?;
        let mut row: user::ActiveModel = row.into();
        row.setup_token_hash = Set(Some(token_hash(&token)));
        row.setup_expires_ms = Set(Some(now_ms + SETUP_LINK_LIFETIME_MS));
        row.update(&transaction)
            .await
            .context("saving a setup link")?;
        record(&transaction, Record::new(Action::NewSetupLink, subject)).await?;
        transaction.commit().await.context("saving a setup link")?;
        Ok(Some(token))
    }

    /// Who a setup link is for, if it still works.
    pub async fn setup_link_user(&self, token: &str, now_ms: i64) -> Result<Option<User>> {
        let row = user::Entity::find()
            .filter(user::Column::SetupTokenHash.eq(token_hash(token)))
            .filter(user::Column::SetupExpiresMs.gt(now_ms))
            .filter(user::Column::DisabledMs.is_null())
            .one(&self.connection)
            .await
            .context("checking a setup link")?;
        Ok(row.map(Into::into))
    }

    /// Sets a password through a setup link, which then stops working. Anyone signed
    /// in as this user is signed out. Returns false if the link had stopped working.
    pub async fn use_setup_link(
        &self,
        user_id: i64,
        token: &str,
        password_hash: &str,
        now_ms: i64,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let before = load(&transaction, user_id).await?;
        // One update, so a link used twice at once can only work once.
        let updated = user::Entity::update_many()
            .col_expr(user::Column::PasswordHash, Expr::value(password_hash))
            .col_expr(
                user::Column::SetupTokenHash,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                user::Column::SetupExpiresMs,
                Expr::value(Option::<i64>::None),
            )
            .filter(user::Column::Id.eq(user_id))
            .filter(user::Column::SetupTokenHash.eq(token_hash(token)))
            .filter(user::Column::SetupExpiresMs.gt(now_ms))
            .filter(user::Column::DisabledMs.is_null())
            .exec(&transaction)
            .await
            .context("saving a password")?;
        if updated.rows_affected != 1 {
            return Ok(false);
        }
        user_session::Entity::delete_many()
            .filter(user_session::Column::UserId.eq(user_id))
            .exec(&transaction)
            .await
            .context("ending sessions")?;
        // Whoever has the link is acting as the user it's for.
        let by = before.as_ref().map(as_actor);
        record_user(&transaction, user_id, before.as_ref(), by).await?;
        transaction.commit().await.context("saving a password")?;
        Ok(true)
    }

    /// Someone who could sign in with this address, with their password's hash.
    /// Someone who can still sign in, by their email address.
    pub async fn active_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let row = user::Entity::find()
            .filter(user::Column::Email.eq(normalise_email(email)))
            .filter(user::Column::DisabledMs.is_null())
            .one(&self.connection)
            .await
            .context("loading a user")?;
        Ok(row.map(User::from))
    }

    pub async fn sign_in_details(&self, email: &str) -> Result<Option<(User, Option<String>)>> {
        let row = user::Entity::find()
            .filter(user::Column::Email.eq(normalise_email(email)))
            .filter(user::Column::DisabledMs.is_null())
            .one(&self.connection)
            .await
            .context("loading a user")?;
        Ok(row.map(|row| {
            let hash = row.password_hash.clone();
            (row.into(), hash)
        }))
    }

    /// Changes a password, and signs the user out everywhere except `keep_session`.
    pub async fn change_password(
        &self,
        id: i64,
        password_hash: &str,
        keep_session: &str,
    ) -> Result<()> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let before = load(&transaction, id).await?;
        user::Entity::update_many()
            .col_expr(user::Column::PasswordHash, Expr::value(password_hash))
            .filter(user::Column::Id.eq(id))
            .exec(&transaction)
            .await
            .context("saving a password")?;
        user_session::Entity::delete_many()
            .filter(user_session::Column::UserId.eq(id))
            .filter(user_session::Column::TokenHash.ne(token_hash(keep_session)))
            .exec(&transaction)
            .await
            .context("ending sessions")?;
        record_user(&transaction, id, before.as_ref(), None).await?;
        transaction.commit().await.context("saving a password")
    }

    /// Returns false if there's no such user.
    pub async fn set_theme(&self, id: i64, theme: &str) -> Result<bool> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let before = load(&transaction, id).await?;
        let updated = user::Entity::update_many()
            .col_expr(user::Column::Theme, Expr::value(theme))
            .filter(user::Column::Id.eq(id))
            .exec(&transaction)
            .await
            .context("saving a theme")?;
        record_user(&transaction, id, before.as_ref(), None).await?;
        transaction.commit().await.context("saving a theme")?;
        Ok(updated.rows_affected == 1)
    }

    /// Returns false if there's no such user.
    pub async fn set_time_zone(&self, id: i64, zone: Tz) -> Result<bool> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let before = load(&transaction, id).await?;
        let updated = user::Entity::update_many()
            .col_expr(user::Column::TimeZone, Expr::value(zone.name()))
            .filter(user::Column::Id.eq(id))
            .exec(&transaction)
            .await
            .context("saving a time zone")?;
        record_user(&transaction, id, before.as_ref(), None).await?;
        transaction.commit().await.context("saving a time zone")?;
        Ok(updated.rows_affected == 1)
    }

    /// Whether anyone else could still sign in without this user.
    async fn is_last_enabled_user(&self, id: i64) -> Result<bool> {
        let others = user::Entity::find()
            .filter(user::Column::Id.ne(id))
            .filter(user::Column::DisabledMs.is_null())
            .count(&self.connection)
            .await
            .context("counting users")?;
        Ok(others == 0)
    }

    /// Stops someone signing in, and signs them out.
    pub async fn disable_user(&self, id: i64, now_ms: i64) -> Result<UserChange> {
        let Some(row) = user::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading a user")?
        else {
            return Ok(UserChange::NoSuchUser);
        };
        if row.disabled_ms.is_some() {
            return Ok(UserChange::Done);
        }
        if self.is_last_enabled_user(id).await? {
            return Ok(UserChange::LastUser);
        }
        let transaction = self.connection.begin().await.context("starting a save")?;
        let before = row.clone();
        let mut row: user::ActiveModel = row.into();
        row.disabled_ms = Set(Some(now_ms));
        row.update(&transaction).await.context("disabling a user")?;
        record_user(&transaction, id, Some(&before), None).await?;
        user_session::Entity::delete_many()
            .filter(user_session::Column::UserId.eq(id))
            .exec(&transaction)
            .await
            .context("ending sessions")?;
        transaction.commit().await.context("disabling a user")?;
        Ok(UserChange::Done)
    }

    pub async fn enable_user(&self, id: i64) -> Result<UserChange> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let before = load(&transaction, id).await?;
        let updated = user::Entity::update_many()
            .col_expr(user::Column::DisabledMs, Expr::value(Option::<i64>::None))
            .filter(user::Column::Id.eq(id))
            .exec(&transaction)
            .await
            .context("enabling a user")?;
        record_user(&transaction, id, before.as_ref(), None).await?;
        transaction.commit().await.context("enabling a user")?;
        Ok(if updated.rows_affected == 1 {
            UserChange::Done
        } else {
            UserChange::NoSuchUser
        })
    }

    pub async fn delete_user(&self, id: i64) -> Result<UserChange> {
        let Some(row) = user::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading a user")?
        else {
            return Ok(UserChange::NoSuchUser);
        };
        if row.disabled_ms.is_none() {
            return Ok(UserChange::StillEnabled);
        }
        let transaction = self.connection.begin().await.context("starting a save")?;
        user_session::Entity::delete_many()
            .filter(user_session::Column::UserId.eq(id))
            .exec(&transaction)
            .await
            .context("ending sessions")?;
        user::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting a user")?;
        record_user(&transaction, id, Some(&row), None).await?;
        transaction.commit().await.context("deleting a user")?;
        Ok(UserChange::Done)
    }

    /// Signs someone in, and gives back the only copy of the session's token. Every
    /// way of signing in ends here.
    pub async fn start_session(&self, user_id: i64, now_ms: i64) -> Result<String> {
        user_session::Entity::delete_many()
            .filter(user_session::Column::ExpiresMs.lte(now_ms))
            .exec(&self.connection)
            .await
            .context("clearing old sessions")?;
        let token = new_nonce()?;
        let transaction = self.connection.begin().await.context("starting a save")?;
        let row = load(&transaction, user_id)
            .await?
            .context("signing in someone who isn't a user")?;
        user_session::ActiveModel {
            user_id: Set(user_id),
            token_hash: Set(token_hash(&token)),
            created_ms: Set(now_ms),
            expires_ms: Set(now_ms + SESSION_LIFETIME_MS),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .context("saving a session")?;
        user::Entity::update_many()
            .col_expr(user::Column::LastSignInMs, Expr::value(now_ms))
            .filter(user::Column::Id.eq(user_id))
            .exec(&transaction)
            .await
            .context("noting a sign in")?;
        let subject = Subject::new(Kind::User, user_id, row.email.clone());
        let entry = Record::new(Action::SignedIn, subject).by(as_actor(&row));
        record(&transaction, entry).await?;
        transaction.commit().await.context("saving a session")?;
        Ok(token)
    }

    /// Who a session belongs to, if it's still good.
    pub async fn session_user(&self, token: &str, now_ms: i64) -> Result<Option<User>> {
        let session = user_session::Entity::find()
            .filter(user_session::Column::TokenHash.eq(token_hash(token)))
            .filter(user_session::Column::ExpiresMs.gt(now_ms))
            .one(&self.connection)
            .await
            .context("checking a session")?;
        let Some(session) = session else {
            return Ok(None);
        };
        let row = user::Entity::find_by_id(session.user_id)
            .filter(user::Column::DisabledMs.is_null())
            .one(&self.connection)
            .await
            .context("loading a session's user")?;
        Ok(row.map(Into::into))
    }

    /// Every secret saved for users and sessions, for checking what's kept.
    #[cfg(test)]
    pub async fn saved_secrets(&self) -> Vec<String> {
        let users = user::Entity::find().all(&self.connection).await.unwrap();
        let sessions = user_session::Entity::find()
            .all(&self.connection)
            .await
            .unwrap();
        let hashes = users
            .into_iter()
            .flat_map(|row| [row.setup_token_hash, row.password_hash]);
        hashes
            .flatten()
            .chain(sessions.into_iter().map(|row| row.token_hash))
            .collect()
    }

    /// Signs out the session with this token, if it's still there.
    pub async fn end_session(&self, token: &str) -> Result<()> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let session = user_session::Entity::find()
            .filter(user_session::Column::TokenHash.eq(token_hash(token)))
            .one(&transaction)
            .await
            .context("checking a session")?;
        let Some(session) = session else {
            return Ok(());
        };
        user_session::Entity::delete_by_id(session.id)
            .exec(&transaction)
            .await
            .context("ending a session")?;
        if let Some(row) = load(&transaction, session.user_id).await? {
            let subject = Subject::new(Kind::User, row.id, row.email.clone());
            let entry = Record::new(Action::SignedOut, subject).by(as_actor(&row));
            record(&transaction, entry).await?;
        }
        transaction.commit().await.context("ending a session")
    }

    /// Notes that someone failed to sign in as `email`, which may be nobody's.
    pub async fn record_failed_sign_in(&self, email: &str, user: Option<&User>) -> Result<()> {
        let subject = Subject {
            kind: Kind::User,
            id: user.map(|user| user.id.to_string()),
            name: normalise_email(email),
        };
        self.record_audit(Record::new(Action::SignInFailed, subject))
            .await
    }
}
