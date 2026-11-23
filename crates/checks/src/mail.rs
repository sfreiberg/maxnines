//! Checks of mail servers: SMTP, IMAP and POP3. Without a username and password,
//! each checks that the server greets it, and whether it offers to upgrade to TLS.
//! With them, it signs in and leaves. Each is timed and its certificate read as a
//! website's is.
//!
//! A password is only ever sent over TLS: from the start where the check says so,
//! as on ports 465, 993 and 995, or after upgrading with STARTTLS. A server that
//! offers neither isn't sent it.

use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use maxnines_protocol::Check;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::sign_in::{Credentials, short};
use crate::{Findings, certificate_verdict, connect, host_and_port, resolve, secure};

/// The username and password a mail check signs in with, if it was given them.
fn login(credentials: Option<&Credentials>) -> Result<Option<(&str, &str)>> {
    let Some(credentials) = credentials.filter(|given| !given.is_empty()) else {
        return Ok(None);
    };
    let username = credentials
        .username
        .as_deref()
        .context("signing in needs a username")?;
    let password = credentials
        .password
        .as_deref()
        .context("signing in needs a password")?;
    Ok(Some((username, password)))
}

const NO_TLS: &str = "it doesn't offer TLS, so the password wasn't sent";

pub(crate) async fn check_smtp(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let login = login(credentials)?;
    let (host, socket) = open(check, findings).await?;
    let local = socket.local_addr().ok();
    if check.tls == Some(true) {
        let secured = secure(&host, socket, &[], findings).await?;
        certificate_verdict(check, secured.problem)?;
        let mut smtp = Smtp::new(secured.stream);
        smtp.greeting().await?;
        let offers = smtp.hello(local).await?;
        return smtp.sign_in(login, &offers, findings).await;
    }
    let mut smtp = Smtp::new(socket);
    smtp.greeting().await?;
    let offers = smtp.hello(local).await?;
    let offered = offers.iter().any(|offer| offer == "STARTTLS");
    findings.tls_offered = Some(offered);
    if login.is_none() {
        return smtp.sign_in(None, &offers, findings).await;
    }
    ensure!(offered, NO_TLS);
    let (code, _) = smtp.command("STARTTLS").await?;
    ensure!(code == 220, NO_TLS);
    // Nothing more comes before the TLS handshake, so nothing is left unread.
    let socket = smtp.reader.into_inner();
    let secured = secure(&host, socket, &[], findings).await?;
    certificate_verdict(check, secured.problem)?;
    let mut smtp = Smtp::new(secured.stream);
    let offers = smtp.hello(local).await?;
    smtp.sign_in(login, &offers, findings).await
}

/// Just enough SMTP for a check: the greeting, EHLO, STARTTLS, signing in and
/// leaving. Nothing is ever sent.
struct Smtp<S> {
    reader: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Smtp<S> {
    fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    /// A reply's code and its lines' text. Every line but the last has a dash
    /// after the code.
    async fn reply(&mut self) -> Result<(u16, Vec<String>)> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let read = (&mut self.reader)
                .take(MAX_LINE as u64)
                .read_line(&mut line)
                .await?;
            ensure!(read > 0, "it closed the connection");
            let line = line.trim_end();
            let code = line
                .get(..3)
                .and_then(|code| code.parse().ok())
                .context("it didn't answer as a mail server does")?;
            lines.push(line.get(4..).unwrap_or_default().to_string());
            if line.as_bytes().get(3) != Some(&b'-') {
                return Ok((code, lines));
            }
            ensure!(
                lines.len() < MAX_LINES,
                "it didn't answer as a mail server does"
            );
        }
    }

    async fn command(&mut self, command: &str) -> Result<(u16, Vec<String>)> {
        let stream = self.reader.get_mut();
        stream.write_all(command.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        self.reply().await
    }

    async fn greeting(&mut self) -> Result<()> {
        let (code, _) = self.reply().await?;
        ensure!(code == 220, "it didn't greet as a mail server does");
        Ok(())
    }

    /// Says hello by this end's address, as a client without a name of its own
    /// does, and gives what the server offers, such as `STARTTLS` or `AUTH PLAIN`,
    /// in capitals.
    async fn hello(&mut self, local: Option<SocketAddr>) -> Result<Vec<String>> {
        let name = match local.map(|address| address.ip()) {
            Some(std::net::IpAddr::V4(address)) => format!("[{address}]"),
            Some(std::net::IpAddr::V6(address)) => format!("[IPv6:{address}]"),
            None => "[127.0.0.1]".to_string(),
        };
        let (code, lines) = self.command(&format!("EHLO {name}")).await?;
        ensure!(code == 250, "it didn't answer as a mail server does");
        Ok(lines
            .into_iter()
            .skip(1)
            .map(|offer| offer.to_ascii_uppercase())
            .collect())
    }

    /// Signs in with PLAIN, or LOGIN where that's all there is, then leaves.
    async fn sign_in(
        &mut self,
        login: Option<(&str, &str)>,
        offers: &[String],
        findings: &mut Findings,
    ) -> Result<()> {
        if let Some((username, password)) = login {
            let ways: Vec<&str> = offers
                .iter()
                .find_map(|offer| offer.strip_prefix("AUTH "))
                .map(|ways| ways.split_whitespace().collect())
                .unwrap_or_default();
            let encode = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
            let accepted = if ways.contains(&"PLAIN") {
                let both = encode(&format!("\0{username}\0{password}"));
                self.command(&format!("AUTH PLAIN {both}")).await?.0 == 235
            } else if ways.contains(&"LOGIN") {
                self.command("AUTH LOGIN").await?.0 == 334
                    && self.command(&encode(username)).await?.0 == 334
                    && self.command(&encode(password)).await?.0 == 235
            } else {
                bail!("it offers no way to sign in that the check knows")
            };
            findings.signed_in = Some(accepted);
            ensure!(accepted, "it didn't accept the username and password");
        }
        let _ = self.command("QUIT").await;
        Ok(())
    }
}

/// A line longer than this isn't a server being reasonable, and nor are this
/// many lines in one reply.
const MAX_LINE: usize = 1024;
const MAX_LINES: usize = 100;

async fn open(check: &Check, findings: &mut Findings) -> Result<(String, TcpStream)> {
    let (host, port) = host_and_port(&check.target)?;
    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;
    Ok((host, socket))
}

pub(crate) async fn check_imap(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let login = login(credentials)?;
    let (host, socket) = open(check, findings).await?;
    if check.tls == Some(true) {
        let secured = secure(&host, socket, &[], findings).await?;
        certificate_verdict(check, secured.problem)?;
        let client = imap_greeted(async_imap::Client::new(secured.stream)).await?;
        return imap_sign_in(client, login, findings).await;
    }
    let mut client = imap_greeted(async_imap::Client::new(socket)).await?;
    let offered = imap_offers_starttls(&mut client).await?;
    findings.tls_offered = Some(offered);
    let Some(login) = login else {
        return Ok(());
    };
    ensure!(offered, NO_TLS);
    client
        .run_command_and_check_ok("STARTTLS", None)
        .await
        .map_err(|_| anyhow!(NO_TLS))?;
    let secured = secure(&host, client.into_inner(), &[], findings).await?;
    certificate_verdict(check, secured.problem)?;
    imap_sign_in(
        async_imap::Client::new(secured.stream),
        Some(login),
        findings,
    )
    .await
}

/// Whether the server lists STARTTLS among what it can do, asked before anything
/// secret is sent.
async fn imap_offers_starttls<T>(client: &mut async_imap::Client<T>) -> Result<bool>
where
    T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    use async_imap::imap_proto::{Capability, RequestId, Response};

    // Its own tag, which the library's own commands never use.
    const TAG: &str = "M1";
    let stream = client.get_mut();
    stream
        .write_all(format!("{TAG} CAPABILITY\r\n").as_bytes())
        .await?;
    stream.flush().await?;
    let asked = RequestId(TAG.to_string());
    let mut offered = false;
    loop {
        let answer = client
            .read_response()
            .await?
            .context("it closed the connection")?;
        match answer.parsed() {
            Response::Capabilities(capabilities) => {
                offered |= capabilities.iter().any(|capability| {
                    matches!(capability, Capability::Atom(name) if name.eq_ignore_ascii_case("STARTTLS"))
                });
            }
            Response::Done { tag, .. } if *tag == asked => return Ok(offered),
            _ => {}
        }
    }
}

/// Waits for the server's greeting, which comes before anything is asked.
async fn imap_greeted<T>(mut client: async_imap::Client<T>) -> Result<async_imap::Client<T>>
where
    T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    let greeting = client
        .read_response()
        .await?
        .context("it closed the connection without a greeting")?;
    ensure!(
        matches!(
            greeting.parsed(),
            async_imap::imap_proto::Response::Data { .. }
        ),
        "it didn't greet as an IMAP server does"
    );
    Ok(client)
}

async fn imap_sign_in<T>(
    client: async_imap::Client<T>,
    login: Option<(&str, &str)>,
    findings: &mut Findings,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    let Some((username, password)) = login else {
        return Ok(());
    };
    match client.login(username, password).await {
        Ok(mut session) => {
            findings.signed_in = Some(true);
            let _ = session.logout().await;
            Ok(())
        }
        Err((error, _)) => {
            findings.signed_in = Some(false);
            match error {
                async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_) => {
                    bail!("it didn't accept the username and password")
                }
                other => Err(short(other)),
            }
        }
    }
}

pub(crate) async fn check_pop3(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let login = login(credentials)?;
    let (host, socket) = open(check, findings).await?;
    if check.tls == Some(true) {
        let secured = secure(&host, socket, &[], findings).await?;
        certificate_verdict(check, secured.problem)?;
        let mut pop = Pop3::new(secured.stream);
        pop.greeting().await?;
        return pop.sign_in(login, findings).await;
    }
    let mut pop = Pop3::new(socket);
    pop.greeting().await?;
    let offered = pop.offers_stls().await;
    findings.tls_offered = Some(offered);
    if login.is_none() {
        let _ = pop.command("QUIT").await;
        return Ok(());
    }
    ensure!(offered, NO_TLS);
    pop.command("STLS").await.map_err(|_| anyhow!(NO_TLS))?;
    // Nothing more comes before the TLS handshake, so nothing is left unread.
    let socket = pop.reader.into_inner();
    let secured = secure(&host, socket, &[], findings).await?;
    certificate_verdict(check, secured.problem)?;
    Pop3::new(secured.stream).sign_in(login, findings).await
}

/// Just enough POP3 for a check: the greeting, STLS, signing in and leaving.
struct Pop3<S> {
    reader: BufReader<S>,
}

/// A line longer than this isn't a server being reasonable.
const MAX_POP3_LINE: usize = 1024;

impl<S: AsyncRead + AsyncWrite + Unpin> Pop3<S> {
    fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    async fn line(&mut self) -> Result<String> {
        let mut line = String::new();
        let read = (&mut self.reader)
            .take(MAX_POP3_LINE as u64)
            .read_line(&mut line)
            .await?;
        ensure!(read > 0, "it closed the connection");
        Ok(line.trim_end().to_string())
    }

    async fn greeting(&mut self) -> Result<()> {
        let greeting = self.line().await?;
        ensure!(
            greeting.starts_with("+OK"),
            "it didn't greet as a POP3 server does"
        );
        Ok(())
    }

    /// Sends a command and gives the rest of its `+OK` line, or fails with
    /// whatever came instead.
    async fn command(&mut self, command: &str) -> Result<String> {
        let stream = self.reader.get_mut();
        stream.write_all(command.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        let answer = self.line().await?;
        answer
            .strip_prefix("+OK")
            .map(|rest| rest.trim().to_string())
            .ok_or_else(|| anyhow!("refused"))
    }

    /// Whether CAPA lists STLS. A server that doesn't know CAPA doesn't offer it.
    async fn offers_stls(&mut self) -> bool {
        if self.command("CAPA").await.is_err() {
            return false;
        }
        let mut offered = false;
        while let Ok(line) = self.line().await {
            if line == "." {
                break;
            }
            offered |= line.eq_ignore_ascii_case("STLS");
        }
        offered
    }

    async fn sign_in(
        &mut self,
        login: Option<(&str, &str)>,
        findings: &mut Findings,
    ) -> Result<()> {
        if let Some((username, password)) = login {
            let accepted = self.command(&format!("USER {username}")).await.is_ok()
                && self.command(&format!("PASS {password}")).await.is_ok();
            findings.signed_in = Some(accepted);
            ensure!(accepted, "it didn't accept the username and password");
        }
        let _ = self.command("QUIT").await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use base64::Engine;
    use maxnines_protocol::CheckKind;
    use serde_json::Value;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::run_signed_in;
    use crate::test_tls::acceptor;

    #[derive(Clone, Copy, PartialEq)]
    enum Protocol {
        Smtp,
        Imap,
        Pop3,
    }

    /// One side of a fake server's connection, before or after TLS.
    enum Conn {
        Plain(BufReader<TcpStream>),
        Tls(Box<BufReader<tokio_rustls::server::TlsStream<TcpStream>>>),
    }

    impl Conn {
        async fn line(&mut self) -> Option<String> {
            let mut line = String::new();
            let read = match self {
                Self::Plain(reader) => reader.read_line(&mut line).await,
                Self::Tls(reader) => reader.read_line(&mut line).await,
            };
            matches!(read, Ok(n) if n > 0).then(|| line.trim_end().to_string())
        }

        async fn send(&mut self, text: &str) {
            let result = match self {
                Self::Plain(reader) => reader.get_mut().write_all(text.as_bytes()).await,
                Self::Tls(reader) => reader.get_mut().write_all(text.as_bytes()).await,
            };
            let _ = result;
        }

        fn secure(&self) -> bool {
            matches!(self, Self::Tls(_))
        }
    }

    /// A mail server that takes `monitor` and `s3cret`, from the start over TLS or
    /// upgrading to it when asked, if it offers to. It notes whether the password
    /// ever came over a plain connection.
    async fn fake(
        protocol: Protocol,
        implicit: bool,
        offers_tls: bool,
    ) -> (SocketAddr, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let leaked = Arc::new(AtomicBool::new(false));
        let noted = leaked.clone();
        let tls = acceptor();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (tls, noted) = (tls.clone(), noted.clone());
                tokio::spawn(async move {
                    let mut conn = if implicit {
                        let Ok(stream) = tls.accept(socket).await else {
                            return;
                        };
                        Conn::Tls(Box::new(BufReader::new(stream)))
                    } else {
                        Conn::Plain(BufReader::new(socket))
                    };
                    serve(protocol, offers_tls, &mut conn, &tls, &noted).await;
                });
            }
        });
        (address, leaked)
    }

    async fn serve(
        protocol: Protocol,
        offers_tls: bool,
        conn: &mut Conn,
        tls: &TlsAcceptor,
        leaked: &AtomicBool,
    ) {
        let greeting = match protocol {
            Protocol::Smtp => "220 fake ESMTP\r\n",
            Protocol::Imap => "* OK fake ready\r\n",
            Protocol::Pop3 => "+OK fake ready\r\n",
        };
        conn.send(greeting).await;
        let mut awaiting_plain = false;
        while let Some(line) = conn.line().await {
            let upper = line.to_uppercase();
            let offer = offers_tls && !conn.secure();
            let mut upgrade = false;
            let reply = match protocol {
                Protocol::Pop3 => match upper.split(' ').next().unwrap_or_default() {
                    "CAPA" => format!(
                        "+OK\r\nUSER\r\n{}.\r\n",
                        if offer { "STLS\r\n" } else { "" }
                    ),
                    "STLS" if offer => {
                        upgrade = true;
                        "+OK begin\r\n".to_string()
                    }
                    "USER" => "+OK\r\n".to_string(),
                    "PASS" => {
                        leaked.fetch_or(!conn.secure(), Ordering::Relaxed);
                        if line.ends_with(" s3cret") {
                            "+OK in\r\n"
                        } else {
                            "-ERR no\r\n"
                        }
                        .to_string()
                    }
                    "QUIT" => {
                        conn.send("+OK bye\r\n").await;
                        return;
                    }
                    _ => "-ERR unknown\r\n".to_string(),
                },
                Protocol::Imap => {
                    let (tag, command) = line.split_once(' ').unwrap_or((&line, ""));
                    let verb = command.split(' ').next().unwrap_or_default().to_uppercase();
                    match verb.as_str() {
                        "CAPABILITY" => format!(
                            "* CAPABILITY IMAP4rev1{}\r\n{tag} OK done\r\n",
                            if offer { " STARTTLS" } else { "" }
                        ),
                        "STARTTLS" if offer => {
                            upgrade = true;
                            format!("{tag} OK begin\r\n")
                        }
                        "LOGIN" => {
                            leaked.fetch_or(!conn.secure(), Ordering::Relaxed);
                            if command.contains("\"monitor\" \"s3cret\"") {
                                format!("{tag} OK in\r\n")
                            } else {
                                format!("{tag} NO wrong\r\n")
                            }
                        }
                        "LOGOUT" => {
                            conn.send(&format!("* BYE\r\n{tag} OK bye\r\n")).await;
                            return;
                        }
                        _ => format!("{tag} BAD unknown\r\n"),
                    }
                }
                Protocol::Smtp => {
                    if awaiting_plain {
                        awaiting_plain = false;
                        leaked.fetch_or(!conn.secure(), Ordering::Relaxed);
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(&line)
                            .unwrap_or_default();
                        if decoded == b"\0monitor\0s3cret" {
                            "235 in\r\n"
                        } else {
                            "535 wrong\r\n"
                        }
                        .to_string()
                    } else {
                        match upper.split(' ').next().unwrap_or_default() {
                            "EHLO" => format!(
                                "250-fake\r\n250-AUTH PLAIN LOGIN\r\n{}250 OK\r\n",
                                if offer { "250-STARTTLS\r\n" } else { "" }
                            ),
                            "STARTTLS" if offer => {
                                upgrade = true;
                                "220 go\r\n".to_string()
                            }
                            "AUTH" => {
                                let given = line.split(' ').nth(2);
                                match given {
                                    Some(encoded) => {
                                        leaked.fetch_or(!conn.secure(), Ordering::Relaxed);
                                        let decoded = base64::engine::general_purpose::STANDARD
                                            .decode(encoded)
                                            .unwrap_or_default();
                                        if decoded == b"\0monitor\0s3cret" {
                                            "235 in\r\n"
                                        } else {
                                            "535 wrong\r\n"
                                        }
                                        .to_string()
                                    }
                                    None => {
                                        awaiting_plain = true;
                                        "334 \r\n".to_string()
                                    }
                                }
                            }
                            "NOOP" | "RSET" => "250 OK\r\n".to_string(),
                            "QUIT" => {
                                conn.send("221 bye\r\n").await;
                                return;
                            }
                            _ => "502 unknown\r\n".to_string(),
                        }
                    }
                }
            };
            conn.send(&reply).await;
            if upgrade {
                let Conn::Plain(reader) =
                    std::mem::replace(conn, Conn::Plain(BufReader::new(dummy().await)))
                else {
                    return;
                };
                let Ok(stream) = tls.accept(reader.into_inner()).await else {
                    return;
                };
                *conn = Conn::Tls(Box::new(BufReader::new(stream)));
            }
        }
    }

    /// Something to hold the place of a connection while it's upgraded.
    async fn dummy() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, _) = tokio::join!(TcpStream::connect(address), listener.accept());
        client.unwrap()
    }

    fn check(kind: CheckKind, address: SocketAddr, implicit: bool) -> Check {
        let mut check = Check::new("mail", kind, &address.to_string());
        check.insecure = Some(true);
        if implicit {
            check.tls = Some(true);
        }
        check
    }

    fn login(password: &str) -> Credentials {
        Credentials {
            username: Some("monitor".to_string()),
            password: Some(password.to_string()),
            private_key: None,
        }
    }

    async fn run(check: &Check, credentials: Option<&Credentials>) -> Value {
        run_signed_in(check, credentials).await
    }

    #[tokio::test]
    async fn each_kind_signs_in_after_upgrading_to_tls_and_from_the_start() {
        for (kind, protocol) in [
            (CheckKind::Smtp, Protocol::Smtp),
            (CheckKind::Imap, Protocol::Imap),
            (CheckKind::Pop3, Protocol::Pop3),
        ] {
            for implicit in [false, true] {
                let (address, leaked) = fake(protocol, implicit, true).await;
                let mail = check(kind, address, implicit);
                let result = run(&mail, None).await;
                assert_eq!(
                    result["up"], 1,
                    "{kind:?} {implicit} without signing in: {result}"
                );
                // Every kind is timed the same way, and says whether it offers TLS.
                for stage in ["dns_secs", "connect_secs", "response_secs"] {
                    assert!(result[stage].is_f64(), "{kind:?} {stage}: {result}");
                }
                if implicit {
                    assert!(result["tls_secs"].is_f64(), "{kind:?}: {result}");
                    assert_eq!(result["cert_valid"], false, "{kind:?}: {result}");
                } else {
                    assert_eq!(result["tls_offered"], true, "{kind:?}: {result}");
                }
                let result = run(&mail, Some(&login("s3cret"))).await;
                assert_eq!(result["signed_in"], true, "{kind:?} {implicit}: {result}");
                assert!(result["tls_secs"].is_f64(), "{kind:?} {implicit}: {result}");
                let result = run(&mail, Some(&login("guess"))).await;
                assert_eq!(
                    result["up"], 0,
                    "{kind:?} {implicit} with a wrong password: {result}"
                );
                assert_eq!(result["signed_in"], false, "{kind:?}: {result}");
                assert!(!result.to_string().contains("guess"), "{result}");
                assert!(
                    !leaked.load(Ordering::Relaxed),
                    "{kind:?} sent a password in the clear"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_password_is_never_sent_to_a_server_without_tls() {
        for (kind, protocol) in [
            (CheckKind::Smtp, Protocol::Smtp),
            (CheckKind::Imap, Protocol::Imap),
            (CheckKind::Pop3, Protocol::Pop3),
        ] {
            let (address, leaked) = fake(protocol, false, false).await;
            let mail = check(kind, address, false);
            let result = run(&mail, None).await;
            assert_eq!(result["up"], 1, "{kind:?} answers");
            assert_eq!(result["tls_offered"], false, "{kind:?}: {result}");
            let result = run(&mail, Some(&login("s3cret"))).await;
            assert_eq!(result["up"], 0, "{kind:?}: {result}");
            assert_eq!(result["error"], NO_TLS, "{kind:?}: {result}");
            assert!(
                !leaked.load(Ordering::Relaxed),
                "{kind:?} sent a password in the clear"
            );
        }
    }
}
