//! Two-factor sign-in with an authenticator app: a secret shared once as a QR
//! code, then a six-digit code that changes every 30 seconds (TOTP, RFC 6238).
//! Recovery codes stand in for a lost phone, and each works once.

use anyhow::{Context, Result, anyhow};
use maxnines_protocol::auth::new_nonce;
use totp_rs::{Builder, Secret, Totp};

/// What authenticator apps show beside the account.
const ISSUER: &str = "MaxNines";
/// Codes from the 30 seconds before and after count too, for clocks that are a
/// little out.
const SKEW_STEPS: u16 = 1;
pub const RECOVERY_CODES: usize = 10;
/// Hex characters in a recovery code, which is 64 random bits.
const RECOVERY_CODE_LEN: usize = 16;

/// A new secret, in the base32 that authenticator apps take when typed in.
pub fn new_secret() -> String {
    Secret::generate().to_base32()
}

fn totp(secret: &str, email: &str) -> Result<Totp> {
    let secret = Secret::try_from_base32(secret).map_err(|_| anyhow!("unreadable secret"))?;
    Builder::new()
        .with_secret(secret)
        .with_skew(SKEW_STEPS)
        .with_account_name(email)
        .with_issuer(Some(ISSUER))
        .build()
        .map_err(|error| anyhow!("setting up two-factor: {error}"))
}

/// Which 30-second step a code belongs to, if it's right for about now. A step is
/// only ever accepted once, which the caller has to see to.
pub fn matching_step(secret: &str, email: &str, code: &str, now_secs: u64) -> Result<Option<u64>> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    Ok(totp(secret, email)?.check(&code, now_secs))
}

/// The code an app would show at a time.
#[cfg(test)]
pub fn code_at(secret: &str, email: &str, secs: u64) -> String {
    totp(secret, email).unwrap().generate(secs).to_string()
}

/// The QR code an app scans to learn the secret, as a PNG.
pub fn qr_png(secret: &str, email: &str) -> Result<Vec<u8>> {
    totp(secret, email)?
        .to_qr_png()
        .map_err(|error| anyhow!("drawing the QR code: {error}"))
}

/// The secret in groups of four, which is easier to type.
pub fn grouped(secret: &str) -> String {
    let groups: Vec<String> = secret
        .as_bytes()
        .chunks(4)
        .map(|group| String::from_utf8_lossy(group).to_string())
        .collect();
    groups.join(" ")
}

/// New recovery codes, like `3f9a-0c2e-77b1-d405`.
pub fn new_recovery_codes() -> Result<Vec<String>> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let random = new_nonce()?;
            let code = random
                .get(..RECOVERY_CODE_LEN)
                .context("too little randomness")?;
            let groups: Vec<&str> = (0..RECOVERY_CODE_LEN)
                .step_by(4)
                .map(|at| &code[at..at + 4])
                .collect();
            Ok(groups.join("-"))
        })
        .collect()
}

/// A recovery code as it's hashed, however it was typed.
pub fn normalise_recovery_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_works_for_its_own_time_and_just_either_side() {
        let secret = new_secret();
        let code = code_at(&secret, "a@example.com", 3000);

        let step = matching_step(&secret, "a@example.com", &code, 3000).unwrap();
        assert_eq!(step, Some(100));
        assert_eq!(
            matching_step(&secret, "a@example.com", &code, 3031).unwrap(),
            Some(100)
        );
        assert_eq!(
            matching_step(&secret, "a@example.com", &code, 2975).unwrap(),
            Some(100)
        );
        assert_eq!(
            matching_step(&secret, "a@example.com", &code, 3090).unwrap(),
            None
        );
        // Apps show it with a space in the middle.
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(
            matching_step(&secret, "a@example.com", &spaced, 3000).unwrap(),
            Some(100)
        );
    }

    #[test]
    fn only_six_digits_are_a_code() {
        let secret = new_secret();
        for wrong in ["", "12345", "1234567", "abcdef", "12345a"] {
            assert_eq!(
                matching_step(&secret, "a@example.com", wrong, 3000).unwrap(),
                None
            );
        }
        let other = new_secret();
        let code = code_at(&other, "a@example.com", 3000);
        assert_eq!(
            matching_step(&secret, "a@example.com", &code, 3000).unwrap(),
            None
        );
    }

    #[test]
    fn the_qr_code_is_a_png_and_secrets_differ() {
        let secret = new_secret();
        assert_ne!(secret, new_secret());
        let png = qr_png(&secret, "a@example.com").unwrap();
        assert!(png.starts_with(b"\x89PNG"));
        assert_eq!(grouped("ABCDEFGHIJ"), "ABCD EFGH IJ");
    }

    #[test]
    fn recovery_codes_are_many_different_and_typed_any_way() {
        let codes = new_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODES);
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), RECOVERY_CODES);
        assert_eq!(codes[0].len(), 19);
        assert_eq!(
            normalise_recovery_code(" 3F9A-0c2e 77b1-D405 "),
            "3f9a0c2e77b1d405"
        );
    }
}
