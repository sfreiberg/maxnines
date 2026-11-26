//! The LDAP check, for directories such as OpenLDAP, 389 Directory Server and Active
//! Directory. Without a username and password, it upgrades to TLS with StartTLS where
//! it's offered, reading the certificate as a website's is, and reads the directory's
//! root entry, which says what the server is and where its data starts. With them, it
//! signs in with a simple bind, then reads the entry its data starts at, timing that
//! search. Nothing is ever written.
//!
//! A password is only ever sent over TLS: from the start where the check says so, as
//! on port 636, or after StartTLS. A server that offers neither isn't sent it.
//!
//! LDAP's messages are BER, which `lber`, the BER library of the `ldap3` client,
//! reads and writes. The client itself makes its own connections and TLS, so it
//! couldn't time them or read the certificate.

use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::BytesMut;
use lber::common::TagClass;
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Boolean, Enumerated, Integer, OctetString};
use maxnines_protocol::Check;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::sign_in::{Credentials, TLS_NOT_OFFERED, username_and_password};
use crate::{
    Closed, Findings, TLS_ANSWER, TLS_ONLY, certificate_verdict, connect, elapsed_secs,
    host_and_port, hung_up, resolve, secure, starts_as_tls,
};

const NOT_LDAP: &str = "it didn't answer as an LDAP server does";
const BUSY: &str = "it's too busy, or unavailable";

/// StartTLS's extended operation.
const START_TLS: &str = "1.3.6.1.4.1.1466.20037";

/// Bigger than any answer the check asks for, and nothing a server needs to send.
const MAX_MESSAGE: usize = 64 * 1024;
/// How deep an answer's structures can go. The check's own go 5 deep, and a deeper
/// one could only be meant to use up the stack that reads it.
const MAX_NESTING: usize = 16;
/// A search of one entry finds one, and refers elsewhere for it at most a few
/// times, so more is a server not being reasonable.
const MAX_ENTRIES: usize = 16;
/// The most of a directory's naming contexts tried, looking for one to read.
const MAX_BASES: usize = 8;

/// What each message does, by its application tag.
const BIND_REQUEST: u64 = 0;
const BIND_RESPONSE: u64 = 1;
const UNBIND_REQUEST: u64 = 2;
const SEARCH_REQUEST: u64 = 3;
const SEARCH_ENTRY: u64 = 4;
const SEARCH_DONE: u64 = 5;
const SEARCH_REFERENCE: u64 = 19;
const EXTENDED_REQUEST: u64 = 23;
const EXTENDED_RESPONSE: u64 = 24;

/// The result codes the check tells apart.
const SUCCESS: i64 = 0;
const NO_SUCH_OBJECT: i64 = 32;
const INVALID_CREDENTIALS: i64 = 49;
const INSUFFICIENT_ACCESS: i64 = 50;
const BUSY_CODE: i64 = 51;
const UNAVAILABLE: i64 = 52;

/// BER's own tags for the universal types the check uses.
const INTEGER: u64 = 2;
const OCTET_STRING: u64 = 4;
const ENUMERATED: u64 = 10;
const SEQUENCE: u64 = 16;

pub(crate) async fn check_ldap(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    // A simple bind with an empty password signs in as nobody, which most servers
    // accept, so it isn't a login.
    let login = username_and_password(credentials, check.kind)?;
    let (host, port) = host_and_port(&check.target)?;
    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;
    if check.tls == Some(true) {
        let secured = secure(&host, socket, &[], findings).await?;
        certificate_verdict(check, secured.problem)?;
        return Ldap::new(secured.stream, 1).look(login, findings).await;
    }
    let mut ldap = Ldap::new(socket, 1);
    let offered = match ldap.start_tls().await {
        Err(_) if ldap.answered_in_tls => bail!(TLS_ANSWER),
        offered => offered?,
    };
    findings.tls_offered = Some(offered == StartTls::Offered);
    match offered {
        StartTls::Offered => {}
        // Some servers and proxies hang up on an operation they don't know, which
        // says nothing about the rest, so it's looked at again without asking. One
        // that hangs up on that too without a word isn't speaking LDAP in the clear.
        StartTls::HungUp => {
            let socket = connect(&addresses, findings).await?;
            let mut plain = Ldap::new(socket, 1);
            let looked = plain.look(None, findings).await;
            if !plain.answered && looked.as_ref().is_err_and(hung_up) {
                findings.tls_offered = None;
                bail!(TLS_ONLY);
            }
            ensure!(login.is_none(), TLS_NOT_OFFERED);
            return looked;
        }
        _ if login.is_some() => {
            ldap.unbind().await;
            bail!(TLS_NOT_OFFERED);
        }
        StartTls::Refused => return ldap.look(None, findings).await,
    }
    // Nothing more comes before the TLS handshake, so nothing is left unread.
    ensure!(ldap.buffer.is_empty(), NOT_LDAP);
    let next_id = ldap.next_id;
    let secured = secure(&host, ldap.stream, &[], findings).await?;
    certificate_verdict(check, secured.problem)?;
    Ldap::new(secured.stream, next_id)
        .look(login, findings)
        .await
}

/// Just enough LDAP for a check: StartTLS, a simple bind, reading one entry and
/// leaving.
struct Ldap<S> {
    stream: S,
    buffer: BytesMut,
    /// Each request on a connection has an ID of its own, which its answers carry.
    next_id: i64,
    /// Whether anything's been read on the connection.
    answered: bool,
    /// Whether the first that was read started as TLS does.
    answered_in_tls: bool,
}

/// How a server answered being asked to upgrade to TLS.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StartTls {
    Offered,
    Refused,
    /// It closed the connection, or said it was ending the session, rather than
    /// answer.
    HungUp,
}

/// What a directory's root entry says about it.
#[derive(Debug, Default)]
struct RootEntry {
    /// Where its data might start, such as `dc=example,dc=com`: Active Directory's
    /// own domain first, then each of the server's naming contexts, as a server can
    /// list one of its own, such as OpenLDAP's `cn=accesslog`, before its data.
    bases: Vec<String>,
    /// What it says it is, which OpenLDAP and Active Directory don't.
    version: Option<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Ldap<S> {
    fn new(stream: S, next_id: i64) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
            next_id,
            answered: false,
            answered_in_tls: false,
        }
    }

    /// Signs in where given a login, and reads the root entry and, signed in, the
    /// entry the data starts at. Always leaves, whatever happened.
    async fn look(&mut self, login: Option<(&str, &str)>, findings: &mut Findings) -> Result<()> {
        let looked = self.look_around(login, findings).await;
        self.unbind().await;
        looked
    }

    async fn look_around(
        &mut self,
        login: Option<(&str, &str)>,
        findings: &mut Findings,
    ) -> Result<()> {
        if let Some((username, password)) = login {
            let code = self.bind(username, password).await?;
            // A server too busy to look at the login hasn't said anything about it.
            if !matches!(code, BUSY_CODE | UNAVAILABLE) {
                findings.signed_in = Some(code == SUCCESS);
            }
            match code {
                SUCCESS => {}
                INVALID_CREDENTIALS => bail!("it didn't accept the username and password"),
                BUSY_CODE | UNAVAILABLE => bail!(BUSY),
                code => bail!("it didn't let the account sign in, with result code {code}"),
            }
        }
        let root = self.root_entry().await?;
        // Reading the data is what shows its database works, and only an account
        // can be expected to be let in to it.
        if login.is_none() {
            findings.server_version = root.ok().and_then(|root| root.version);
            return Ok(());
        }
        let root = match root {
            Ok(root) => root,
            Err(INSUFFICIENT_ACCESS) => {
                bail!("the account isn't allowed to read the directory's root entry")
            }
            Err(code) => bail!("reading its root entry failed, with result code {code}"),
        };
        findings.server_version = root.version;
        findings.search_secs = Some(self.read_data(&root.bases).await?);
        Ok(())
    }

    /// Asks to upgrade to TLS, saying how the server answered.
    async fn start_tls(&mut self) -> Result<StartTls> {
        let name = context_primitive(0, START_TLS.as_bytes());
        let id = self
            .send(constructed(
                TagClass::Application,
                EXTENDED_REQUEST,
                vec![name],
            ))
            .await?;
        match self.answer(id, EXTENDED_RESPONSE).await {
            Ok((SUCCESS, _)) => Ok(StartTls::Offered),
            Ok(_) => Ok(StartTls::Refused),
            Err(error)
                if error.is::<std::io::Error>() || error.is::<Closed>() || error.is::<Ended>() =>
            {
                Ok(StartTls::HungUp)
            }
            Err(error) => Err(error),
        }
    }

    async fn bind(&mut self, username: &str, password: &str) -> Result<i64> {
        let request = constructed(
            TagClass::Application,
            BIND_REQUEST,
            vec![
                integer(3),
                octets(username.as_bytes()),
                context_primitive(0, password.as_bytes()),
            ],
        );
        let id = self.send(request).await?;
        Ok(self.answer(id, BIND_RESPONSE).await?.0)
    }

    /// Reads the root entry, which anyone may, though some servers won't let in
    /// someone who hasn't signed in. That still answers as LDAP, and gives the
    /// result code it was turned down with.
    async fn root_entry(&mut self) -> Result<std::result::Result<RootEntry, i64>> {
        let attributes = [
            "namingContexts",
            "defaultNamingContext",
            "vendorName",
            "vendorVersion",
        ];
        let (code, entries) = self.search("", &attributes).await?;
        match code {
            SUCCESS => {}
            BUSY_CODE | UNAVAILABLE => bail!(BUSY),
            code => return Ok(Err(code)),
        }
        let Some(entry) = entries.into_iter().next() else {
            return Ok(Ok(RootEntry::default()));
        };
        let values = |name: &str| -> Vec<String> {
            entry
                .iter()
                .filter(|(attribute, _)| attribute.eq_ignore_ascii_case(name))
                .flat_map(|(_, values)| values.iter().cloned())
                .filter(|value| !value.is_empty())
                .collect()
        };
        let first = |name: &str| values(name).into_iter().next();
        let version = match (first("vendorName"), first("vendorVersion")) {
            (_, Some(version)) => Some(version),
            (name, None) => name,
        };
        let mut bases = values("defaultNamingContext");
        for base in values("namingContexts") {
            if !bases.iter().any(|known| known.eq_ignore_ascii_case(&base)) {
                bases.push(base);
            }
        }
        bases.truncate(MAX_BASES);
        Ok(Ok(RootEntry { bases, version }))
    }

    /// Reads the entry the directory's data starts at, asking for none of its
    /// attributes, which is enough for the server to have found it in its database,
    /// and gives how long that took in seconds. Each of `bases` is tried in turn
    /// until one can be read, which is the one timed, and when none can, it's the
    /// first that says why.
    async fn read_data(&mut self, bases: &[String]) -> Result<f64> {
        let mut first_failure = None;
        for base in bases {
            let started = Instant::now();
            let (code, _) = self.search(base, &["1.1"]).await?;
            match code {
                SUCCESS => return Ok(elapsed_secs(started)),
                BUSY_CODE | UNAVAILABLE => bail!(BUSY),
                code => {
                    first_failure.get_or_insert(code);
                }
            }
        }
        match first_failure {
            Some(NO_SUCH_OBJECT) => bail!("the entry its data starts at wasn't found"),
            Some(INSUFFICIENT_ACCESS) => bail!("the account isn't allowed to read the directory"),
            Some(code) => bail!("searching it failed, with result code {code}"),
            None => bail!("its root entry doesn't say where its data is, so it couldn't be read"),
        }
    }

    /// A search of the one entry at `base`, giving the result code and each entry
    /// found, as its attributes and their values.
    async fn search(
        &mut self,
        base: &str,
        attributes: &[&str],
    ) -> Result<(i64, Vec<Vec<(String, Vec<String>)>>)> {
        let request = constructed(
            TagClass::Application,
            SEARCH_REQUEST,
            vec![
                octets(base.as_bytes()),
                // Only the entry itself, never following aliases.
                enumerated(0),
                enumerated(0),
                // One entry, in at most 10 seconds.
                integer(1),
                integer(10),
                Boolean::default().into_structure(),
                // Every entry has an objectClass, so this matches whatever's there.
                context_primitive(7, b"objectClass"),
                universal_sequence(
                    attributes
                        .iter()
                        .map(|attribute| octets(attribute.as_bytes()))
                        .collect(),
                ),
            ],
        );
        let id = self.send(request).await?;
        let mut entries = Vec::new();
        let mut references = 0;
        loop {
            let op = self.message(id).await?;
            ensure!(op.class == TagClass::Application, NOT_LDAP);
            match op.id {
                SEARCH_ENTRY => {
                    ensure!(entries.len() < MAX_ENTRIES, NOT_LDAP);
                    entries.push(read_attributes(op).context(NOT_LDAP)?);
                }
                // Somewhere else to look, which the check never follows.
                SEARCH_REFERENCE => {
                    references += 1;
                    ensure!(references <= MAX_ENTRIES, NOT_LDAP);
                }
                SEARCH_DONE => return Ok((result_code(&op).context(NOT_LDAP)?, entries)),
                _ => bail!(NOT_LDAP),
            }
        }
    }

    async fn unbind(&mut self) {
        let unbind = StructureTag {
            class: TagClass::Application,
            id: UNBIND_REQUEST,
            payload: PL::P(Vec::new()),
        };
        let _ = self.send(unbind).await;
        let _ = self.stream.shutdown().await;
    }

    /// Sends a request, giving its ID.
    async fn send(&mut self, op: StructureTag) -> Result<i64> {
        let id = self.next_id;
        self.next_id += 1;
        let message = universal_sequence(vec![integer(id), op]);
        let mut bytes = BytesMut::new();
        lber::write::encode_into(&mut bytes, message)?;
        self.stream.write_all(&bytes).await?;
        Ok(id)
    }

    /// The result code of the answer to request `id`, which has to be an `op`, and
    /// the answer itself.
    async fn answer(&mut self, id: i64, op: u64) -> Result<(i64, StructureTag)> {
        let answer = self.message(id).await?;
        ensure!(
            answer.class == TagClass::Application && answer.id == op,
            NOT_LDAP
        );
        Ok((result_code(&answer).context(NOT_LDAP)?, answer))
    }

    /// The next message's operation, which has to answer request `id`. A server
    /// ending the session says so with an unasked-for message of ID 0.
    async fn message(&mut self, id: i64) -> Result<StructureTag> {
        let message = self.read_message().await?;
        let mut parts = message
            .expect_constructed()
            .filter(|parts| parts.len() >= 2)
            .context(NOT_LDAP)?
            .into_iter();
        let (Some(answers), Some(op)) = (parts.next(), parts.next()) else {
            bail!(NOT_LDAP);
        };
        let answers = universal_integer(answers).context(NOT_LDAP)?;
        if answers == 0 {
            return Err(Ended.into());
        }
        ensure!(answers == id, NOT_LDAP);
        Ok(op)
    }

    /// Reads one whole message, which is one BER sequence.
    async fn read_message(&mut self) -> Result<StructureTag> {
        loop {
            if let Some(length) = message_length(&self.buffer)? {
                let bytes = self.buffer.split_to(length);
                ensure!(nesting_within(&bytes, MAX_NESTING), NOT_LDAP);
                let (rest, message) =
                    lber::parse::parse_tag(&bytes).map_err(|_| anyhow!(NOT_LDAP))?;
                ensure!(rest.is_empty(), NOT_LDAP);
                ensure!(
                    message.class == TagClass::Universal && message.id == SEQUENCE,
                    NOT_LDAP
                );
                return Ok(message);
            }
            let read = self.stream.read_buf(&mut self.buffer).await?;
            if read == 0 {
                return Err(Closed.into());
            }
            if !self.answered {
                self.answered_in_tls = starts_as_tls(&self.buffer);
            }
            self.answered = true;
        }
    }
}

/// A server sending a notice of disconnection, as it does before closing.
#[derive(Debug)]
struct Ended;

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("it ended the session")
    }
}

impl std::error::Error for Ended {}

/// A BER header at the start of `bytes`: its tag byte, how long the header is, and
/// how long what follows it is. None until enough has come to say, and an error
/// for what LDAP never sends: a tag number that takes more bytes, which `lber`
/// would read differently, or a length that's to be found later or takes more than
/// 4 bytes.
fn ber_header(bytes: &[u8]) -> Result<Option<(u8, usize, usize)>> {
    let (Some(&tag), Some(&length)) = (bytes.first(), bytes.get(1)) else {
        return Ok(None);
    };
    ensure!(tag & 0x1f != 0x1f, NOT_LDAP);
    if length < 0x80 {
        return Ok(Some((tag, 2, usize::from(length))));
    }
    let count = usize::from(length & 0x7f);
    ensure!((1..=4).contains(&count), NOT_LDAP);
    let Some(digits) = bytes.get(2..2 + count) else {
        return Ok(None);
    };
    let length = digits
        .iter()
        .fold(0usize, |total, &byte| total << 8 | usize::from(byte));
    Ok(Some((tag, 2 + count, length)))
}

/// How long the message at the start of `buffer` is in all, once enough of it has
/// come to say. Only an LDAP message's outer sequence is read here, so anything
/// else, or one too long, isn't LDAP.
fn message_length(buffer: &[u8]) -> Result<Option<usize>> {
    // A universal, constructed sequence.
    ensure!(buffer.first().is_none_or(|&tag| tag == 0x30), NOT_LDAP);
    let Some((_, header, content)) = ber_header(buffer)? else {
        return Ok(None);
    };
    ensure!(content <= MAX_MESSAGE, NOT_LDAP);
    let total = header + content;
    Ok((buffer.len() >= total).then_some(total))
}

/// Whether BER no deeper than `limit`, read as `lber` reads it, is all `bytes`
/// holds, checked without recursing, as `lber` recurses once for each level.
fn nesting_within(mut bytes: &[u8], limit: usize) -> bool {
    // Where each structure being read ends, as how much is left after it.
    let mut ends: Vec<usize> = Vec::new();
    while !bytes.is_empty() {
        while ends.last() == Some(&bytes.len()) {
            ends.pop();
        }
        let Ok(Some((tag, header, length))) = ber_header(bytes) else {
            return false;
        };
        let rest = &bytes[header..];
        if length > rest.len() || ends.last().is_some_and(|&end| rest.len() - length < end) {
            return false;
        }
        if tag & 0x20 != 0 {
            ends.push(rest.len() - length);
            if ends.len() > limit {
                return false;
            }
            bytes = rest;
        } else {
            bytes = &rest[length..];
        }
    }
    true
}

fn constructed(class: TagClass, id: u64, parts: Vec<StructureTag>) -> StructureTag {
    StructureTag {
        class,
        id,
        payload: PL::C(parts),
    }
}

fn universal_sequence(parts: Vec<StructureTag>) -> StructureTag {
    constructed(TagClass::Universal, SEQUENCE, parts)
}

fn context_primitive(id: u64, bytes: &[u8]) -> StructureTag {
    StructureTag {
        class: TagClass::Context,
        id,
        payload: PL::P(bytes.to_vec()),
    }
}

fn integer(value: i64) -> StructureTag {
    Integer {
        inner: value,
        ..Integer::default()
    }
    .into_structure()
}

fn enumerated(value: i64) -> StructureTag {
    Enumerated {
        inner: value,
        ..Enumerated::default()
    }
    .into_structure()
}

fn octets(bytes: &[u8]) -> StructureTag {
    OctetString {
        inner: bytes.to_vec(),
        ..OctetString::default()
    }
    .into_structure()
}

/// A whole number of up to 8 bytes, as BER writes them, most significant first and
/// signed.
fn number(bytes: &[u8]) -> Option<i64> {
    let (&first, _) = bytes.split_first()?;
    if bytes.len() > 8 {
        return None;
    }
    let start = if first & 0x80 != 0 { -1i64 } else { 0 };
    Some(
        bytes
            .iter()
            .fold(start, |total, &byte| total << 8 | i64::from(byte)),
    )
}

fn universal_integer(tag: StructureTag) -> Option<i64> {
    let tag = tag.match_class(TagClass::Universal)?.match_id(INTEGER)?;
    number(&tag.expect_primitive()?)
}

/// An answer's result code, the first part of every LDAP result.
fn result_code(op: &StructureTag) -> Option<i64> {
    let PL::C(parts) = &op.payload else {
        return None;
    };
    let code = parts.first()?;
    match (&code.class, code.id, &code.payload) {
        (TagClass::Universal, ENUMERATED, PL::P(bytes)) => number(bytes),
        _ => None,
    }
}

fn text(tag: StructureTag) -> Option<String> {
    let tag = tag
        .match_class(TagClass::Universal)?
        .match_id(OCTET_STRING)?;
    String::from_utf8(tag.expect_primitive()?).ok()
}

/// A search entry's attributes, each with its values.
fn read_attributes(entry: StructureTag) -> Option<Vec<(String, Vec<String>)>> {
    let mut parts = entry.expect_constructed()?.into_iter();
    let _name = parts.next()?;
    let attributes = parts.next()?.expect_constructed()?;
    attributes
        .into_iter()
        .map(|attribute| {
            let mut parts = attribute.expect_constructed()?.into_iter();
            let name = text(parts.next()?)?;
            let values = parts
                .next()?
                .expect_constructed()?
                .into_iter()
                .filter_map(text)
                .collect();
            Some((name, values))
        })
        .collect()
}

/// Reads whole messages from the start of `buffer`, for the fake server in tests.
#[cfg(test)]
fn take_message(buffer: &mut BytesMut) -> Option<StructureTag> {
    let length = message_length(buffer).ok()??;
    let bytes = buffer.split_to(length);
    let (_, message) = lber::parse::parse_tag(&bytes).ok()?;
    Some(message)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use maxnines_protocol::CheckKind;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::run_signed_in;
    use crate::test_tls::acceptor;

    const ACCOUNT: &str = "cn=monitor,dc=example,dc=com";
    const BASE: &str = "dc=example,dc=com";
    /// How long the fake takes to refuse a read of its log.
    const SLOW_REFUSAL: std::time::Duration = std::time::Duration::from_millis(300);

    /// How a fake server offers TLS.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Tls {
        Never,
        /// After StartTLS.
        Upgrade,
        /// From the start, as on port 636.
        Implicit,
        /// Hangs up on being asked to upgrade, as some proxies do with an
        /// operation they don't know.
        HangsUp,
    }

    /// Who a fake server lets search.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Anonymous {
        /// Anyone may read the root entry, as most servers let them.
        Allowed,
        /// Only an account that's signed in, as a server set to need that does.
        Refused,
        /// No one may read the root entry, though a signed-in account may read
        /// the data.
        RootClosed,
        /// It answers every search with nothing but places to look elsewhere.
        Referrals,
    }

    struct Fake {
        tls: Tls,
        anonymous: Anonymous,
        seen: Arc<Seen>,
    }

    /// What a fake saw, for a test to look at.
    #[derive(Default)]
    struct Seen {
        /// Whether a password ever came over a plain connection.
        leaked: AtomicBool,
        /// When it last finished refusing a read of its log, just before saying so.
        refused: std::sync::Mutex<Option<std::time::Instant>>,
    }

    /// Where a fake's connection is, which lasts through an upgrade to TLS.
    #[derive(Default)]
    struct Session {
        secure: bool,
        signed_in: bool,
    }

    async fn fake(tls: Tls, anonymous: Anonymous) -> (SocketAddr, Arc<Seen>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Seen::default());
        let noted = seen.clone();
        let acceptor = acceptor();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let fake = Arc::new(Fake {
                    tls,
                    anonymous,
                    seen: noted.clone(),
                });
                let acceptor = acceptor.clone();
                tokio::spawn(async move { fake.serve(socket, &acceptor).await });
            }
        });
        (address, seen)
    }

    fn reply(id: i64, op: StructureTag) -> BytesMut {
        let mut bytes = BytesMut::new();
        lber::write::encode_into(&mut bytes, universal_sequence(vec![integer(id), op])).unwrap();
        bytes
    }

    fn result(op: u64, code: i64) -> StructureTag {
        constructed(
            TagClass::Application,
            op,
            vec![enumerated(code), octets(b""), octets(b"")],
        )
    }

    fn entry(name: &str, attributes: &[(&str, &str)]) -> StructureTag {
        let attributes = attributes
            .iter()
            .map(|(attribute, value)| {
                universal_sequence(vec![
                    octets(attribute.as_bytes()),
                    constructed(TagClass::Universal, 17, vec![octets(value.as_bytes())]),
                ])
            })
            .collect();
        constructed(
            TagClass::Application,
            SEARCH_ENTRY,
            vec![octets(name.as_bytes()), universal_sequence(attributes)],
        )
    }

    impl Fake {
        async fn serve(&self, mut socket: TcpStream, acceptor: &TlsAcceptor) {
            let mut session = Session::default();
            if self.tls != Tls::Implicit && !self.answer(&mut socket, &mut session).await {
                return;
            }
            let Ok(mut stream) = acceptor.accept(socket).await else {
                return;
            };
            session.secure = true;
            self.answer(&mut stream, &mut session).await;
        }

        /// Answers requests until the connection ends, or the client asks to
        /// upgrade to TLS and is told yes, which gives true.
        async fn answer<S: AsyncRead + AsyncWrite + Unpin>(
            &self,
            stream: &mut S,
            session: &mut Session,
        ) -> bool {
            let mut buffer = BytesMut::new();
            loop {
                let Some(message) = take_message(&mut buffer) else {
                    match stream.read_buf(&mut buffer).await {
                        Ok(n) if n > 0 => continue,
                        _ => return false,
                    }
                };
                let mut parts = message.expect_constructed().unwrap().into_iter();
                let id = universal_integer(parts.next().unwrap()).unwrap();
                let op = parts.next().unwrap();
                let answer = match op.id {
                    EXTENDED_REQUEST if self.tls == Tls::Upgrade && !session.secure => {
                        let answer = reply(id, result(EXTENDED_RESPONSE, SUCCESS));
                        stream.write_all(&answer).await.unwrap();
                        return true;
                    }
                    EXTENDED_REQUEST if self.tls == Tls::HangsUp => return false,
                    // Unavailable, as Active Directory says without a certificate.
                    EXTENDED_REQUEST => reply(id, result(EXTENDED_RESPONSE, UNAVAILABLE)),
                    BIND_REQUEST => {
                        let mut parts = op.expect_constructed().unwrap().into_iter();
                        let _version = parts.next();
                        let name = text(parts.next().unwrap()).unwrap();
                        let password = parts.next().unwrap().expect_primitive().unwrap();
                        self.seen
                            .leaked
                            .fetch_or(!session.secure, Ordering::Relaxed);
                        session.signed_in = name == ACCOUNT && password == b"s3cret";
                        let code = if session.signed_in {
                            SUCCESS
                        } else if password == b"busy" {
                            BUSY_CODE
                        } else {
                            INVALID_CREDENTIALS
                        };
                        reply(id, result(BIND_RESPONSE, code))
                    }
                    SEARCH_REQUEST => {
                        let base = text(op.expect_constructed().unwrap().remove(0)).unwrap();
                        let mut answer = BytesMut::new();
                        let refused = match self.anonymous {
                            Anonymous::Allowed => false,
                            Anonymous::Refused => !session.signed_in,
                            Anonymous::RootClosed => base.is_empty(),
                            Anonymous::Referrals => {
                                let elsewhere = constructed(
                                    TagClass::Application,
                                    SEARCH_REFERENCE,
                                    vec![octets(b"ldap://elsewhere.example.com/")],
                                );
                                for _ in 0..100 {
                                    answer.extend(reply(id, elsewhere.clone()));
                                }
                                false
                            }
                        };
                        let code = if refused {
                            INSUFFICIENT_ACCESS
                        } else if base.is_empty() {
                            // Its own log comes first, which no account can read,
                            // as OpenLDAP's accesslog can.
                            answer.extend(reply(
                                id,
                                entry(
                                    "",
                                    &[
                                        ("namingContexts", "cn=accesslog"),
                                        ("namingContexts", BASE),
                                        ("vendorName", "Fake Directory"),
                                        ("vendorVersion", "Fake Directory 2.1"),
                                    ],
                                ),
                            ));
                            SUCCESS
                        } else if base == BASE {
                            answer.extend(reply(id, entry(BASE, &[])));
                            SUCCESS
                        } else if base == "cn=accesslog" {
                            // Slow, so timing it with the data's own read shows.
                            tokio::time::sleep(SLOW_REFUSAL).await;
                            *self.seen.refused.lock().unwrap() = Some(std::time::Instant::now());
                            INSUFFICIENT_ACCESS
                        } else {
                            NO_SUCH_OBJECT
                        };
                        answer.extend(reply(id, result(SEARCH_DONE, code)));
                        answer
                    }
                    _ => return false,
                };
                stream.write_all(&answer).await.unwrap();
            }
        }
    }

    fn check(address: SocketAddr, tls: Tls) -> Check {
        let mut check = Check::new("directory", CheckKind::Ldap, &address.to_string());
        check.insecure = Some(true);
        if tls == Tls::Implicit {
            check.tls = Some(true);
        }
        check
    }

    fn login(username: &str, password: &str) -> Credentials {
        Credentials {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            private_key: None,
        }
    }

    #[tokio::test]
    async fn it_signs_in_and_searches_after_upgrading_to_tls_and_from_the_start() {
        for tls in [Tls::Upgrade, Tls::Implicit] {
            let (address, seen) = fake(tls, Anonymous::Allowed).await;
            let ldap = check(address, tls);
            let result = run_signed_in(&ldap, None).await;
            assert_eq!(result["up"], 1, "{tls:?} without signing in: {result}");
            for stage in ["dns_secs", "connect_secs", "tls_secs", "response_secs"] {
                assert!(result[stage].is_f64(), "{tls:?} {stage}: {result}");
            }
            assert_eq!(result["server_version"], "Fake Directory 2.1", "{result}");
            assert!(result["cert_days_left"].is_i64(), "{tls:?}: {result}");
            // Only an account is expected to read the data.
            assert!(result.get("search_secs").is_none(), "{tls:?}: {result}");
            if tls == Tls::Upgrade {
                assert_eq!(result["tls_offered"], true, "{result}");
            }

            let result = run_signed_in(&ldap, Some(&login(ACCOUNT, "s3cret"))).await;
            assert_eq!(result["up"], 1, "{tls:?}: {result}");
            assert_eq!(result["signed_in"], true, "{tls:?}: {result}");
            // Only the read that worked is timed, not the refused one before it,
            // so its time fits in what's passed since the refusal was sent. The
            // refusal was slow, so a time that started before it wouldn't.
            let since_refused = seen.refused.lock().unwrap().unwrap().elapsed();
            let searched = result["search_secs"].as_f64().unwrap();
            assert!(
                searched <= since_refused.as_secs_f64(),
                "{tls:?}: {result}, {since_refused:?} since the refusal"
            );

            let result = run_signed_in(&ldap, Some(&login(ACCOUNT, "guess"))).await;
            assert_eq!(result["up"], 0, "{tls:?} with a wrong password: {result}");
            assert_eq!(result["signed_in"], false, "{tls:?}: {result}");
            assert!(!result.to_string().contains("guess"), "{result}");
            assert!(
                !seen.leaked.load(Ordering::Relaxed),
                "{tls:?} sent a password in the clear"
            );
        }
    }

    #[tokio::test]
    async fn a_password_is_never_sent_to_a_server_without_tls() {
        let (address, seen) = fake(Tls::Never, Anonymous::Allowed).await;
        let ldap = check(address, Tls::Never);
        let result = run_signed_in(&ldap, None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["tls_offered"], false, "{result}");
        assert!(result.get("tls_secs").is_none(), "{result}");

        let result = run_signed_in(&ldap, Some(&login(ACCOUNT, "s3cret"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["error"], TLS_NOT_OFFERED, "{result}");
        assert!(
            !seen.leaked.load(Ordering::Relaxed),
            "sent a password in the clear"
        );
    }

    #[tokio::test]
    async fn a_server_that_hangs_up_on_starttls_is_looked_at_again_without_it() {
        let (address, seen) = fake(Tls::HangsUp, Anonymous::Allowed).await;
        let ldap = check(address, Tls::HangsUp);
        let result = run_signed_in(&ldap, None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["tls_offered"], false, "{result}");
        assert_eq!(result["server_version"], "Fake Directory 2.1", "{result}");

        let result = run_signed_in(&ldap, Some(&login(ACCOUNT, "s3cret"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["error"], TLS_NOT_OFFERED, "{result}");
        assert!(!seen.leaked.load(Ordering::Relaxed));
    }

    /// An LDAPS port reached without tls set answers in TLS, or hangs up without
    /// a word, as OpenLDAP's does, and either is said to be why.
    #[tokio::test]
    async fn an_ldaps_port_without_tls_set_says_so() {
        let (address, seen) = fake(Tls::Implicit, Anonymous::Allowed).await;
        let silent = crate::test_tls::hangs_up().await;
        for (address, why) in [(address, crate::TLS_ANSWER), (silent, crate::TLS_ONLY)] {
            let ldap = check(address, Tls::Never);
            for login in [None, Some(login(ACCOUNT, "s3cret"))] {
                let result = run_signed_in(&ldap, login.as_ref()).await;
                assert_eq!(result["up"], 0, "{result}");
                assert_eq!(result["error"], why, "{result}");
                assert!(result.get("tls_offered").is_none(), "{result}");
            }
        }
        assert!(!seen.leaked.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_busy_server_says_nothing_about_the_login() {
        let (address, _) = fake(Tls::Upgrade, Anonymous::Allowed).await;
        let result =
            run_signed_in(&check(address, Tls::Upgrade), Some(&login(ACCOUNT, "busy"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["error"], BUSY, "{result}");
        assert!(result.get("signed_in").is_none(), "{result}");
    }

    #[tokio::test]
    async fn an_empty_password_is_not_a_login() {
        let (address, _) = fake(Tls::Upgrade, Anonymous::Allowed).await;
        let result = run_signed_in(&check(address, Tls::Upgrade), Some(&login(ACCOUNT, ""))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["error"], "signing in needs a password", "{result}");
    }

    #[tokio::test]
    async fn an_account_that_cannot_read_the_root_entry_is_down() {
        let (address, _) = fake(Tls::Upgrade, Anonymous::RootClosed).await;
        let ldap = check(address, Tls::Upgrade);
        let result = run_signed_in(&ldap, None).await;
        assert_eq!(result["up"], 1, "{result}");

        let result = run_signed_in(&ldap, Some(&login(ACCOUNT, "s3cret"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["signed_in"], true, "{result}");
        assert_eq!(
            result["error"], "the account isn't allowed to read the directory's root entry",
            "{result}"
        );
    }

    #[tokio::test]
    async fn endless_referrals_are_not_taken_for_an_answer() {
        let (address, _) = fake(Tls::Never, Anonymous::Referrals).await;
        let result = run_signed_in(&check(address, Tls::Never), None).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["error"], NOT_LDAP, "{result}");
    }

    #[tokio::test]
    async fn a_server_that_needs_signing_in_to_search_is_still_up() {
        let (address, _) = fake(Tls::Upgrade, Anonymous::Refused).await;
        let ldap = check(address, Tls::Upgrade);
        let result = run_signed_in(&ldap, None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert!(result.get("server_version").is_none(), "{result}");

        let result = run_signed_in(&ldap, Some(&login(ACCOUNT, "s3cret"))).await;
        assert_eq!(result["up"], 1, "{result}");
        assert!(result["search_secs"].is_f64(), "{result}");
    }

    #[tokio::test]
    async fn a_bad_certificate_is_down_unless_it_is_not_minded() {
        for tls in [Tls::Upgrade, Tls::Implicit] {
            let (address, _) = fake(tls, Anonymous::Allowed).await;
            let mut strict = check(address, tls);
            strict.insecure = None;
            let result = run_signed_in(&strict, None).await;
            assert_eq!(result["up"], 0, "{tls:?}: {result}");
            assert!(result["cert_days_left"].is_i64(), "{tls:?}: {result}");
        }
    }

    #[tokio::test]
    async fn something_else_is_not_taken_for_ldap() {
        // A deeply nested answer is turned down before it's read.
        let mut nested = vec![0x04, 0x00];
        for _ in 0..40 {
            let mut outer = vec![0x30, u8::try_from(nested.len()).unwrap()];
            outer.extend(&nested);
            nested = outer;
        }
        for answer in [
            b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
            b"220 mail.example.com ESMTP\r\n".to_vec(),
            nested,
            // Far longer than anything it asks for.
            vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff],
            // A tag number that takes more bytes, which lber reads differently.
            vec![0x30, 0x02, 0x1f, 0x00],
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let answer = answer.clone();
                    tokio::spawn(async move {
                        let mut request = [0u8; 256];
                        let _ = socket.read(&mut request).await;
                        let _ = socket.write_all(&answer).await;
                        let mut rest = Vec::new();
                        let _ = socket.read_to_end(&mut rest).await;
                    });
                }
            });
            let result = run_signed_in(&check(address, Tls::Never), None).await;
            assert_eq!(result["up"], 0, "{result}");
            assert_eq!(result["error"], NOT_LDAP, "{result}");
        }
    }

    #[test]
    fn nesting_is_measured_without_recursing() {
        let mut nested = vec![0x04, 0x01, b'x'];
        for depth in 1..=20 {
            let mut outer = vec![0x30, u8::try_from(nested.len()).unwrap()];
            outer.extend(&nested);
            nested = outer;
            assert_eq!(nesting_within(&nested, 16), depth <= 16, "{depth}");
        }
        // A tag number that takes more bytes, which lber reads as a length.
        // Read as a tag number of more bytes, this was one empty part and then
        // another, but lber reads it as a part of tag 31, then three more.
        assert!(!nesting_within(
            &[0x30, 0x05, 0x1f, 0x00, 0x00, 0x00, 0x00],
            16
        ));
        // A part claiming more than its structure holds.
        assert!(!nesting_within(&[0x30, 0x03, 0x04, 0x05, 0x00], 16));
        assert!(!nesting_within(&[0x30, 0x80, 0x00, 0x00], 16));
        assert!(nesting_within(&[0x30, 0x00, 0x04, 0x00], 16));
    }

    #[test]
    fn numbers_read_as_ber_writes_them() {
        for value in [0i64, 1, 3, 127, 128, 255, 256, 65_535, i64::from(i32::MAX)] {
            let StructureTag { payload, .. } = integer(value);
            let PL::P(bytes) = payload else { panic!() };
            assert_eq!(number(&bytes), Some(value), "{value}");
        }
        assert_eq!(number(&[0xff]), Some(-1));
        assert_eq!(number(&[0x80]), Some(-128));
        assert_eq!(number(&[0xff, 0x7f]), Some(-129));
        assert_eq!(number(&[]), None);
        assert_eq!(number(&[1; 9]), None);
    }
}
