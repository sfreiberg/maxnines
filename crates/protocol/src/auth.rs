//! How agents prove who they are. Each agent owns an Ed25519 key, and its ID is
//! derived from the public key, so an ID can't be claimed without the key.
//!
//! The server sends a one-time nonce and the agent signs it along with the URL
//! it believes it is talking to. The nonce stops a captured response from being
//! replayed, and the URL stops one being relayed to a different server.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

const CONTEXT: &str = "maxnines-agent-auth-v1";
const PUBLIC_KEY_LEN: usize = 32;
/// Half of a SHA-256 hash, as hex.
const AGENT_ID_LEN: usize = 32;

/// An agent's key pair.
pub struct Identity {
    key: Ed25519KeyPair,
}

impl Identity {
    /// Generates a new private key, encoded as PKCS#8 for storing on disk.
    pub fn generate() -> Result<Vec<u8>> {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow!("generating key"))?;
        Ok(document.as_ref().to_vec())
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8(bytes).map_err(|e| anyhow!("invalid key: {e}"))?;
        Ok(Self { key })
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.public_key().as_ref())
    }

    pub fn id(&self) -> String {
        id_for(self.key.public_key().as_ref())
    }

    /// Signs a challenge from the server at `audience`.
    pub fn sign(&self, audience: &str, nonce: &str) -> String {
        hex::encode(self.key.sign(&signed_message(audience, nonce)).as_ref())
    }
}

/// Checks a challenge response, returning the agent's ID if it is valid.
pub fn verify(public_key: &str, audience: &str, nonce: &str, signature: &str) -> Result<String> {
    let key = hex::decode(public_key).context("public key is not hex")?;
    anyhow::ensure!(
        key.len() == PUBLIC_KEY_LEN,
        "public key has the wrong length"
    );
    let signature = hex::decode(signature).context("signature is not hex")?;

    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&signed_message(audience, nonce), &signature)
        .map_err(|_| anyhow!("signature does not match"))?;

    Ok(id_for(&key))
}

/// A random one-time challenge.
pub fn new_nonce() -> Result<String> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("generating nonce"))?;
    Ok(hex::encode(bytes))
}

/// Creates a file only its owner can read on Unix. On Windows it gets the
/// folder's permissions. Fails if the file already exists.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

fn id_for(public_key: &[u8]) -> String {
    let mut id = hex::encode(digest(&SHA256, public_key));
    id.truncate(AGENT_ID_LEN);
    id
}

fn signed_message(audience: &str, nonce: &str) -> Vec<u8> {
    format!("{CONTEXT}\n{audience}\n{nonce}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "wss://monitor.example.com/ws";

    fn identity() -> Identity {
        Identity::from_pkcs8(&Identity::generate().unwrap()).unwrap()
    }

    #[test]
    fn a_valid_response_verifies_and_gives_the_agent_id() {
        let agent = identity();
        let signature = agent.sign(SERVER, "nonce");

        let id = verify(&agent.public_key(), SERVER, "nonce", &signature).unwrap();

        assert_eq!(id, agent.id());
        assert_eq!(id.len(), AGENT_ID_LEN);
    }

    #[test]
    fn a_response_can_not_be_replayed_against_a_new_nonce() {
        let agent = identity();
        let signature = agent.sign(SERVER, "old");
        assert!(verify(&agent.public_key(), SERVER, "new", &signature).is_err());
    }

    #[test]
    fn a_response_can_not_be_relayed_to_another_server() {
        let agent = identity();
        let signature = agent.sign("wss://evil.example.com/ws", "nonce");
        assert!(verify(&agent.public_key(), SERVER, "nonce", &signature).is_err());
    }

    #[test]
    fn another_agents_key_does_not_verify() {
        let signature = identity().sign(SERVER, "nonce");
        assert!(verify(&identity().public_key(), SERVER, "nonce", &signature).is_err());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(verify("zz", SERVER, "nonce", "00").is_err());
        assert!(verify("00", SERVER, "nonce", "00").is_err());
        assert!(verify(&identity().public_key(), SERVER, "nonce", "zz").is_err());
    }

    #[test]
    fn keys_round_trip_through_their_stored_form() {
        let bytes = Identity::generate().unwrap();
        let first = Identity::from_pkcs8(&bytes).unwrap();
        let second = Identity::from_pkcs8(&bytes).unwrap();
        assert_eq!(first.id(), second.id());
    }

    #[test]
    fn nonces_are_unique() {
        assert_ne!(new_nonce().unwrap(), new_nonce().unwrap());
    }
}
