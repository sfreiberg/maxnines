//! Hashing passwords and slowing down guessing. Hashing is slow and takes memory on
//! purpose, so it runs away from the async threads and only a few at a time.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::LazyLock;

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tokio::sync::Semaphore;

const MAX_HASHES_AT_ONCE: usize = 4;
/// Tries at one address from one place, then one more each minute.
const ACCOUNT_BURST: u32 = 5;
/// Tries from one place, which may be a whole office, then one more every 10 seconds.
const SOURCE_BURST: u32 = 30;
/// How many places to remember before forgetting the ones that have calmed down.
const MAX_REMEMBERED: usize = 10_000;

static HASHING: Semaphore = Semaphore::const_new(MAX_HASHES_AT_ONCE);

/// Checked when there's no real hash, so a wrong address takes as long as a wrong
/// password and doesn't show which addresses exist.
static STAND_IN_HASH: LazyLock<String> = LazyLock::new(|| {
    Argon2::default()
        .hash_password(b"there is no password here")
        .map(|hash| hash.to_string())
        .unwrap_or_default()
});

pub async fn hash_password(password: String) -> Result<String> {
    let _turn = HASHING.acquire().await.context("waiting to hash")?;
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
            .map_err(|error| anyhow!("hashing a password: {error}"))
    })
    .await
    .context("hashing a password")?
}

/// Whether a password fits a hash. With no hash, this takes the same time to say no.
pub async fn password_matches(password: String, hash: Option<String>) -> Result<bool> {
    let _turn = HASHING.acquire().await.context("waiting to hash")?;
    tokio::task::spawn_blocking(move || {
        let found = hash.is_some();
        let hash = hash.unwrap_or_else(|| STAND_IN_HASH.clone());
        let parsed =
            PasswordHash::new(&hash).map_err(|error| anyhow!("reading a hash: {error}"))?;
        let matches = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        Ok(found && matches)
    })
    .await
    .context("checking a password")?
}

/// Limits how fast passwords and two-factor codes can be guessed. Limiting one place
/// trying one address means someone else can't lock a person out by guessing from
/// elsewhere.
pub struct SignInThrottle {
    accounts: DefaultKeyedRateLimiter<(IpAddr, String)>,
    sources: DefaultKeyedRateLimiter<IpAddr>,
}

impl Default for SignInThrottle {
    fn default() -> Self {
        let burst = |limit| NonZeroU32::new(limit).unwrap_or(NonZeroU32::MIN);
        let per_minute = Quota::per_minute(NonZeroU32::MIN).allow_burst(burst(ACCOUNT_BURST));
        let per_ten_secs = Quota::per_minute(burst(6)).allow_burst(burst(SOURCE_BURST));
        Self {
            accounts: RateLimiter::keyed(per_minute),
            sources: RateLimiter::keyed(per_ten_secs),
        }
    }
}

/// Where a try comes from, as far as limiting goes: an IPv4 address, or the /64 an IPv6
/// address is in, as one network is usually given a whole /64 to pick addresses from.
fn place(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V4(_) => source,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let network = u128::from(v6) & !u128::from(u64::MAX);
                IpAddr::V6(Ipv6Addr::from(network))
            }
        },
    }
}

impl SignInThrottle {
    /// Whether this try can go ahead. Every try counts, right or wrong.
    pub fn allow(&self, source: IpAddr, email: &str) -> bool {
        let source = place(source);
        if self.accounts.len() > MAX_REMEMBERED {
            self.accounts.retain_recent();
        }
        if self.sources.len() > MAX_REMEMBERED {
            self.sources.retain_recent();
        }
        self.sources.check_key(&source).is_ok()
            && self
                .accounts
                .check_key(&(source, email.to_string()))
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_password_matches_its_own_hash_only() {
        let hash = hash_password("correct horse battery".to_string())
            .await
            .unwrap();

        assert!(hash.starts_with("$argon2id$"));
        assert!(!hash.contains("correct"));
        let right = "correct horse battery".to_string();
        assert!(password_matches(right, Some(hash.clone())).await.unwrap());
        let wrong = "wrong horse battery".to_string();
        assert!(!password_matches(wrong, Some(hash)).await.unwrap());
    }

    #[tokio::test]
    async fn nothing_matches_a_missing_password() {
        for guess in ["", "there is no password here"] {
            assert!(!password_matches(guess.to_string(), None).await.unwrap());
        }
    }

    #[test]
    fn guessing_at_one_address_stops_without_locking_out_anyone_else() {
        let throttle = SignInThrottle::default();
        let attacker: IpAddr = "10.0.0.1".parse().unwrap();
        let owner: IpAddr = "10.0.0.2".parse().unwrap();

        for _ in 0..ACCOUNT_BURST {
            assert!(throttle.allow(attacker, "a@example.com"));
        }
        assert!(!throttle.allow(attacker, "a@example.com"));
        assert!(throttle.allow(attacker, "b@example.com"));
        assert!(throttle.allow(owner, "a@example.com"));
    }

    #[test]
    fn a_network_counts_as_one_place_whichever_of_its_addresses_it_uses() {
        let throttle = SignInThrottle::default();
        for number in 0..ACCOUNT_BURST {
            let source: IpAddr = format!("2001:db8:1:2::{number:x}").parse().unwrap();
            assert!(throttle.allow(source, "a@example.com"));
        }
        let elsewhere_in_it: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        assert!(!throttle.allow(elsewhere_in_it, "a@example.com"));
        // The next network along is another place.
        let next: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(throttle.allow(next, "a@example.com"));
        // An IPv4 address written as IPv6 is the same place as itself.
        for _ in 0..ACCOUNT_BURST {
            assert!(throttle.allow("10.0.0.1".parse().unwrap(), "b@example.com"));
        }
        assert!(!throttle.allow("::ffff:10.0.0.1".parse().unwrap(), "b@example.com"));
        assert!(throttle.allow("10.0.0.2".parse().unwrap(), "b@example.com"));
    }

    #[test]
    fn one_place_can_only_try_so_many_addresses() {
        let throttle = SignInThrottle::default();
        let source: IpAddr = "10.0.0.1".parse().unwrap();

        for number in 0..SOURCE_BURST {
            assert!(throttle.allow(source, &format!("{number}@example.com")));
        }
        assert!(!throttle.allow(source, "next@example.com"));
    }
}
