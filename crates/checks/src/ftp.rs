//! The FTP check. Without a username and password, it checks that the server greets
//! as FTP, and upgrades to TLS with `AUTH TLS` where it's offered, reading the
//! certificate as a website's is. With them, it signs in and leaves. Nothing is ever
//! listed, fetched or sent: no data connection is opened.
//!
//! A password is only ever sent over TLS: from the start where the check says so, as
//! on port 990, or after `AUTH TLS`. A server that offers neither isn't sent it.

use anyhow::{Context, Result, bail, ensure};
use maxnines_protocol::Check;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::sign_in::{Credentials, Password, TLS_NOT_OFFERED, username_and_password};
use crate::{Findings, certificate_verdict, connect, host_and_port, resolve, secure};

const NOT_FTP: &str = "it didn't answer as an FTP server does";

/// A line longer than this isn't a server being reasonable, and nor are this many
/// lines in one reply.
const MAX_LINE: u64 = 1024;
const MAX_LINES: usize = 100;

pub(crate) async fn check_ftp(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let login = username_and_password(credentials, Password::Needed)?;
    let (host, port) = host_and_port(&check.target)?;
    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;
    if check.tls == Some(true) {
        let secured = secure(&host, socket, &[], findings).await?;
        certificate_verdict(check, secured.problem)?;
        let mut ftp = Ftp::new(secured.stream);
        ftp.greeting().await?;
        return ftp.sign_in(login, findings).await;
    }
    let mut ftp = Ftp::new(socket);
    ftp.greeting().await?;
    let (code, _) = ftp.command("AUTH TLS").await?;
    let offered = code == 234;
    findings.tls_offered = Some(offered);
    if !offered {
        if login.is_some() {
            ftp.quit().await;
            bail!(TLS_NOT_OFFERED);
        }
        return ftp.sign_in(None, findings).await;
    }
    // Nothing more comes before the TLS handshake, so nothing is left unread.
    let socket: TcpStream = ftp.reader.into_inner();
    let secured = secure(&host, socket, &[], findings).await?;
    certificate_verdict(check, secured.problem)?;
    Ftp::new(secured.stream).sign_in(login, findings).await
}

/// Just enough FTP for a check: the greeting, `AUTH TLS`, signing in and leaving.
struct Ftp<S> {
    reader: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Ftp<S> {
    fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    async fn line(&mut self) -> Result<String> {
        let mut line = String::new();
        let read = (&mut self.reader)
            .take(MAX_LINE)
            .read_line(&mut line)
            .await?;
        ensure!(read > 0, "it closed the connection");
        Ok(line.trim_end().to_string())
    }

    /// A reply's code and its text. A reply of several lines starts with the code
    /// and a dash, and ends with a line starting with the same code and a space.
    async fn reply(&mut self) -> Result<(u16, String)> {
        let first = self.line().await?;
        let code: u16 = first
            .get(..3)
            .and_then(|code| code.parse().ok())
            .context(NOT_FTP)?;
        let text = first.get(4..).unwrap_or_default().to_string();
        if first.as_bytes().get(3) == Some(&b'-') {
            let end = format!("{code} ");
            for _ in 0..MAX_LINES {
                let line = self.line().await?;
                if line.starts_with(&end) || line == end.trim_end() {
                    return Ok((code, text));
                }
            }
            bail!(NOT_FTP);
        }
        Ok((code, text))
    }

    async fn command(&mut self, command: &str) -> Result<(u16, String)> {
        let stream = self.reader.get_mut();
        stream.write_all(command.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        self.reply().await
    }

    /// The greeting, which can say first that the server will be ready shortly.
    async fn greeting(&mut self) -> Result<()> {
        let (mut code, _) = self.reply().await?;
        if code == 120 {
            code = self.reply().await?.0;
        }
        ensure!(code != 421, "it isn't taking connections now");
        ensure!(code == 220, NOT_FTP);
        Ok(())
    }

    /// Signs in where given a login, then leaves.
    async fn sign_in(mut self, login: Option<(&str, &str)>, findings: &mut Findings) -> Result<()> {
        if let Some((username, password)) = login {
            let accepted = match self.command(&format!("USER {username}")).await?.0 {
                // Signed in on the username alone.
                230 => true,
                331 => matches!(
                    self.command(&format!("PASS {password}")).await?.0,
                    230 | 202
                ),
                _ => false,
            };
            findings.signed_in = Some(accepted);
            if !accepted {
                self.quit().await;
                bail!("it didn't accept the username and password");
            }
        }
        self.quit().await;
        Ok(())
    }

    async fn quit(&mut self) {
        let _ = self.command("QUIT").await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use maxnines_protocol::CheckKind;
    use serde_json::Value;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::run_signed_in;
    use crate::test_tls::acceptor;

    /// How a fake server offers TLS.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Tls {
        Never,
        /// After `AUTH TLS`.
        Upgrade,
        /// From the start, as on port 990.
        Implicit,
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
            let _ = match self {
                Self::Plain(reader) => reader.get_mut().write_all(text.as_bytes()).await,
                Self::Tls(reader) => reader.get_mut().write_all(text.as_bytes()).await,
            };
        }

        fn secure(&self) -> bool {
            matches!(self, Self::Tls(_))
        }
    }

    /// An FTP server that takes `monitor` and `s3cret`, and notes whether the
    /// password ever came over a plain connection. Its greeting and its answer to
    /// `USER` take several lines, as some servers' do.
    async fn fake(tls: Tls) -> (SocketAddr, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let leaked = Arc::new(AtomicBool::new(false));
        let noted = leaked.clone();
        let acceptor = acceptor();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, noted) = (acceptor.clone(), noted.clone());
                tokio::spawn(async move {
                    let mut conn = if tls == Tls::Implicit {
                        let Ok(stream) = acceptor.accept(socket).await else {
                            return;
                        };
                        Conn::Tls(Box::new(BufReader::new(stream)))
                    } else {
                        Conn::Plain(BufReader::new(socket))
                    };
                    serve(tls, &mut conn, &acceptor, &noted).await;
                });
            }
        });
        (address, leaked)
    }

    async fn serve(tls: Tls, conn: &mut Conn, acceptor: &TlsAcceptor, leaked: &AtomicBool) {
        conn.send("220-Welcome to the fake FTP server\r\n  for tests\r\n220 Ready\r\n")
            .await;
        while let Some(line) = conn.line().await {
            let (verb, argument) = line.split_once(' ').unwrap_or((&line, ""));
            let mut upgrade = false;
            let reply = match verb.to_uppercase().as_str() {
                "AUTH" if tls == Tls::Upgrade && !conn.secure() => {
                    upgrade = true;
                    "234 Proceed with negotiation.\r\n"
                }
                "AUTH" => "502 Not offered.\r\n",
                "USER" => "331-Please give\r\n331 the password.\r\n",
                "PASS" => {
                    leaked.fetch_or(!conn.secure(), Ordering::Relaxed);
                    if argument == "s3cret" {
                        "230 Signed in.\r\n"
                    } else {
                        "530 Login incorrect.\r\n"
                    }
                }
                "QUIT" => {
                    conn.send("221 Goodbye.\r\n").await;
                    return;
                }
                _ => "500 Unknown command.\r\n",
            };
            conn.send(reply).await;
            if upgrade {
                let placeholder = Conn::Plain(BufReader::new(dummy().await));
                let Conn::Plain(reader) = std::mem::replace(conn, placeholder) else {
                    return;
                };
                let Ok(stream) = acceptor.accept(reader.into_inner()).await else {
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

    fn check(address: SocketAddr, tls: Tls) -> Check {
        let mut check = Check::new("files", CheckKind::Ftp, &address.to_string());
        check.insecure = Some(true);
        if tls == Tls::Implicit {
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

    #[tokio::test]
    async fn it_signs_in_after_upgrading_to_tls_and_from_the_start() {
        for tls in [Tls::Upgrade, Tls::Implicit] {
            let (address, leaked) = fake(tls).await;
            let ftp = check(address, tls);
            let result = run_signed_in(&ftp, None).await;
            assert_eq!(result["up"], 1, "{tls:?} without signing in: {result}");
            for stage in ["dns_secs", "connect_secs", "tls_secs", "response_secs"] {
                assert!(result[stage].is_f64(), "{tls:?} {stage}: {result}");
            }
            // It read the certificate even without signing in.
            assert!(result["cert_days_left"].is_i64(), "{tls:?}: {result}");
            assert_eq!(result["cert_valid"], false, "{tls:?}: {result}");
            if tls == Tls::Upgrade {
                assert_eq!(result["tls_offered"], true, "{result}");
            }

            let result = run_signed_in(&ftp, Some(&login("s3cret"))).await;
            assert_eq!(result["up"], 1, "{tls:?}: {result}");
            assert_eq!(result["signed_in"], true, "{tls:?}: {result}");

            let result = run_signed_in(&ftp, Some(&login("guess"))).await;
            assert_eq!(result["up"], 0, "{tls:?} with a wrong password: {result}");
            assert_eq!(result["signed_in"], false, "{tls:?}: {result}");
            assert!(!result.to_string().contains("guess"), "{result}");
            assert!(
                !leaked.load(Ordering::Relaxed),
                "{tls:?} sent a password in the clear"
            );
        }
    }

    #[tokio::test]
    async fn a_password_is_never_sent_to_a_server_without_tls() {
        let (address, leaked) = fake(Tls::Never).await;
        let ftp = check(address, Tls::Never);
        let result = run_signed_in(&ftp, None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["tls_offered"], false, "{result}");
        assert!(result.get("tls_secs").is_none(), "{result}");

        let result = run_signed_in(&ftp, Some(&login("s3cret"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["error"], TLS_NOT_OFFERED, "{result}");
        assert!(
            !leaked.load(Ordering::Relaxed),
            "sent a password in the clear"
        );
    }

    #[tokio::test]
    async fn a_bad_certificate_is_down_unless_it_is_not_minded() {
        for tls in [Tls::Upgrade, Tls::Implicit] {
            let (address, _) = fake(tls).await;
            let mut strict = check(address, tls);
            strict.insecure = None;
            let result = run_signed_in(&strict, None).await;
            assert_eq!(result["up"], 0, "{tls:?}: {result}");
            assert!(result["cert_days_left"].is_i64(), "{tls:?}: {result}");
        }
    }

    #[tokio::test]
    async fn something_else_is_not_taken_for_ftp() {
        for greeting in [
            "SSH-2.0-OpenSSH_9.6\r\n",
            "421 Too many users.\r\n",
            "+OK POP3\r\n",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let _ = socket.write_all(greeting.as_bytes()).await;
                    // Held open, so the check reads the greeting, not a closed connection.
                    tokio::spawn(async move {
                        let mut rest = Vec::new();
                        let _ = socket.read_to_end(&mut rest).await;
                    });
                }
            });
            let result: Value = run_signed_in(&check(address, Tls::Never), None).await;
            assert_eq!(result["up"], 0, "{greeting:?}: {result}");
        }
    }
}
