//! The MQTT check, for brokers such as Mosquitto, EMQX and HiveMQ, in MQTT 3.1.1,
//! which every broker speaks. It connects with a clean session, signing in where
//! given a username and password, and leaves. Given a topic, it subscribes to it,
//! sends a test message there and times how long the message takes to come back.
//!
//! MQTT has no way to upgrade to TLS, so TLS is used from the start where the check
//! says so, as on port 8883. A password goes as it is, so as for Redis, it's only
//! sent without TLS to the host itself.
//!
//! The packets are rumqttc's, its MQTT client's. The client itself makes its own
//! connections and TLS, so it couldn't time them or read the certificate.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::BytesMut;
use maxnines_protocol::Check;
use rumqttc::mqttbytes::v4::{ConnAck, ConnectReturnCode, Packet, SubscribeReasonCode};
use rumqttc::mqttbytes::{Error as PacketError, QoS};
use rumqttc::{Connect, Publish, Subscribe};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout_at;

use crate::sign_in::{Credentials, is_loopback};
use crate::{
    Findings, certificate_verdict, connect, elapsed_secs, host_and_port, limit, resolve, secure,
};

const NOT_MQTT: &str = "it didn't answer as an MQTT broker does";
const NO_TLS: &str =
    "a password is only sent without TLS to the host itself, so set tls for one elsewhere";

/// Far more than anything a broker answers the check with. A message someone else
/// sends to the test topic can be bigger, and is skipped without being kept.
const MAX_PACKET: usize = 64 * 1024;
/// How long the broker waits to hear from the check before giving up on it.
const KEEP_ALIVE_SECS: u16 = 30;
/// What's left of the check's time when the test message is given up on, so that
/// it's reported as never coming back rather than the whole check timing out.
const MESSAGE_MARGIN: Duration = Duration::from_millis(250);
/// How many other messages on the test topic are passed over waiting for the
/// check's own.
const MAX_OTHER_MESSAGES: usize = 1000;

/// The username and password the check signs in with, if it was given them. MQTT
/// lets a client give a username alone, but never a password alone.
fn login(credentials: Option<&Credentials>) -> Result<Option<(&str, &str)>> {
    let Some(credentials) = credentials.filter(|given| !given.is_empty()) else {
        return Ok(None);
    };
    let username = credentials
        .username
        .as_deref()
        .filter(|username| !username.is_empty())
        .context("signing in needs a username")?;
    Ok(Some((
        username,
        credentials.password.as_deref().unwrap_or_default(),
    )))
}

pub(crate) async fn check_mqtt(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let deadline = Instant::now() + limit(check).saturating_sub(MESSAGE_MARGIN);
    let login = login(credentials)?;
    let (host, port) = host_and_port(&check.target)?;
    let tls = check.tls == Some(true);
    if login.is_some_and(|(_, password)| !password.is_empty()) {
        ensure!(tls || is_loopback(&host), NO_TLS);
    }
    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;
    if tls {
        let secured = secure(&host, socket, &[], findings).await?;
        certificate_verdict(check, secured.problem)?;
        return Mqtt::new(secured.stream)
            .look(check, login, deadline, findings)
            .await;
    }
    Mqtt::new(socket)
        .look(check, login, deadline, findings)
        .await
}

/// Just enough MQTT for a check: connecting, a test message, and leaving.
struct Mqtt<S> {
    stream: S,
    buffer: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Mqtt<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
        }
    }

    /// Connects, and sends the test message where there's a topic for it. Always
    /// leaves, whatever happened.
    async fn look(
        mut self,
        check: &Check,
        login: Option<(&str, &str)>,
        deadline: Instant,
        findings: &mut Findings,
    ) -> Result<()> {
        let looked = self.look_around(check, login, deadline, findings).await;
        let _ = self.send(Packet::Disconnect).await;
        let _ = self.stream.shutdown().await;
        looked
    }

    async fn look_around(
        &mut self,
        check: &Check,
        login: Option<(&str, &str)>,
        deadline: Instant,
        findings: &mut Findings,
    ) -> Result<()> {
        // The ID only has to be unique for as long as the check is connected, and
        // 23 characters is all a broker has to take.
        let client_id = format!("maxnines-{:012x}", rand::random::<u64>() >> 16);
        let mut hello = Connect::new(client_id);
        hello.keep_alive = KEEP_ALIVE_SECS;
        if let Some((username, password)) = login {
            hello.set_login(username, password);
        }
        self.send(Packet::Connect(hello)).await?;
        let answer = self.conn_ack().await?;
        let needs_login = matches!(
            answer.code,
            ConnectReturnCode::BadUserNamePassword | ConnectReturnCode::NotAuthorized
        );
        if login.is_some() {
            findings.signed_in = Some(answer.code == ConnectReturnCode::Success);
        }
        match answer.code {
            ConnectReturnCode::Success => {}
            _ if needs_login && login.is_some() => {
                bail!("it didn't accept the username and password")
            }
            // It answered as a broker, which is all a check without a login asks,
            // unless it's to send a test message.
            _ if needs_login && check.topic.is_none() => return Ok(()),
            _ if needs_login => bail!("it needs signing in to send the test message"),
            ConnectReturnCode::RefusedProtocolVersion => {
                bail!("it doesn't speak MQTT 3.1.1")
            }
            ConnectReturnCode::BadClientId => bail!("it turned down the check's client ID"),
            ConnectReturnCode::ServiceUnavailable => bail!("it isn't taking connections now"),
            _ => bail!(NOT_MQTT),
        }
        if let Some(topic) = &check.topic {
            let started = Instant::now();
            timeout_at(deadline.into(), self.round_trip(topic))
                .await
                .map_err(|_| {
                    anyhow!(
                        "the test message didn't come back in time, as it doesn't when the \
                         account isn't allowed to send to the topic or read it"
                    )
                })??;
            findings.round_trip_secs = Some(elapsed_secs(started));
        }
        Ok(())
    }

    /// Subscribes to `topic`, then sends a message there that no one else would and
    /// waits for it. Both are at most once, so the broker keeps nothing for later,
    /// and it isn't retained, so nothing's left on the topic.
    async fn round_trip(&mut self, topic: &str) -> Result<()> {
        let mut subscribe = Subscribe::new(topic, QoS::AtMostOnce);
        subscribe.pkid = 1;
        self.send(Packet::Subscribe(subscribe)).await?;
        loop {
            match self.packet().await? {
                Packet::SubAck(answer) if answer.pkid == 1 => {
                    ensure!(
                        matches!(
                            answer.return_codes.as_slice(),
                            [SubscribeReasonCode::Success(_)]
                        ),
                        "it didn't let the check subscribe to the topic"
                    );
                    break;
                }
                // A message retained on the topic can come first.
                Packet::Publish(_) => {}
                _ => bail!(NOT_MQTT),
            }
        }
        let payload = format!("MaxNines check {:016x}", rand::random::<u64>());
        self.send(Packet::Publish(Publish::new(
            topic,
            QoS::AtMostOnce,
            payload.as_bytes(),
        )))
        .await?;
        for _ in 0..MAX_OTHER_MESSAGES {
            match self.packet().await? {
                Packet::Publish(message) if message.payload == payload.as_bytes() => {
                    return Ok(());
                }
                Packet::Publish(_) => {}
                _ => bail!(NOT_MQTT),
            }
        }
        bail!("the topic is too busy to find the test message on")
    }

    /// The broker's answer to connecting, which is always the first thing it
    /// sends: a type byte of 0x20 and 2 bytes after it. Anything else is turned
    /// down at once, rather than waited on as the start of a longer packet, as a
    /// server greeting in text would be.
    async fn conn_ack(&mut self) -> Result<ConnAck> {
        while self.buffer.len() < 2 {
            let read = self.stream.read_buf(&mut self.buffer).await?;
            ensure!(read > 0, "it closed the connection");
        }
        ensure!(self.buffer[..2] == [0x20, 0x02], NOT_MQTT);
        match self.packet().await? {
            Packet::ConnAck(answer) => Ok(answer),
            _ => bail!(NOT_MQTT),
        }
    }

    async fn send(&mut self, packet: Packet) -> Result<()> {
        let mut bytes = BytesMut::new();
        packet
            .write(&mut bytes, MAX_PACKET)
            .map_err(|_| anyhow!("the request couldn't be made"))?;
        self.stream.write_all(&bytes).await?;
        Ok(())
    }

    /// The next whole packet. One too big to be meant for the check is skipped
    /// rather than kept.
    async fn packet(&mut self) -> Result<Packet> {
        let mut skipping = 0usize;
        loop {
            if skipping > 0 {
                let dropped = skipping.min(self.buffer.len());
                let _ = self.buffer.split_to(dropped);
                skipping -= dropped;
            }
            if skipping == 0 {
                match Packet::read(&mut self.buffer, MAX_PACKET) {
                    Ok(packet) => return Ok(packet),
                    Err(PacketError::InsufficientBytes(_)) => {}
                    Err(PacketError::PayloadSizeLimitExceeded(length)) => {
                        // Only a message can be this big: its header, then the rest.
                        ensure!(
                            self.buffer.first().is_some_and(|byte| byte >> 4 == 3),
                            NOT_MQTT
                        );
                        skipping = header_length(length) + length;
                        continue;
                    }
                    Err(_) => bail!(NOT_MQTT),
                }
            }
            let read = self.stream.read_buf(&mut self.buffer).await?;
            ensure!(read > 0, "it closed the connection");
        }
    }
}

/// How long a packet's fixed header is with `remaining` bytes after it: a byte for
/// its type, then the length in 7-bit pieces.
fn header_length(remaining: usize) -> usize {
    let mut pieces = 1;
    let mut left = remaining >> 7;
    while left > 0 {
        pieces += 1;
        left >>= 7;
    }
    1 + pieces
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use maxnines_protocol::CheckKind;
    use rumqttc::mqttbytes::v4::SubAck;
    use tokio::net::TcpListener;

    use super::*;
    use crate::run_signed_in;
    use crate::test_tls::acceptor;

    /// How a fake broker behaves.
    #[derive(Clone, Copy, PartialEq, Debug)]
    struct Broker {
        tls: bool,
        /// Takes only `monitor` and `s3cret`, rather than anyone.
        needs_login: bool,
        /// Lets the check subscribe and send, but never passes messages on, as a
        /// broker whose rules don't let an account send to a topic does.
        drops_messages: bool,
    }

    const OPEN: Broker = Broker {
        tls: false,
        needs_login: false,
        drops_messages: false,
    };

    /// A broker that passes each message back to whoever sent it, after a
    /// retained message and one someone else sent, as a busy topic has. It notes
    /// whether a password ever came over a plain connection.
    async fn fake(broker: Broker) -> (SocketAddr, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let leaked = Arc::new(AtomicBool::new(false));
        let noted = leaked.clone();
        let acceptor = acceptor();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, noted) = (acceptor.clone(), noted.clone());
                tokio::spawn(async move {
                    if broker.tls {
                        if let Ok(stream) = acceptor.accept(socket).await {
                            serve(broker, Mqtt::new(stream), &noted).await;
                        }
                    } else {
                        serve(broker, Mqtt::new(socket), &noted).await;
                    }
                });
            }
        });
        (address, leaked)
    }

    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        broker: Broker,
        mut conn: Mqtt<S>,
        leaked: &AtomicBool,
    ) {
        while let Ok(packet) = conn.packet().await {
            match packet {
                Packet::Connect(hello) => {
                    let given = hello.login.as_ref();
                    if given.is_some_and(|login| !login.password.is_empty()) {
                        leaked.fetch_or(!broker.tls, Ordering::Relaxed);
                    }
                    let accepted = given.is_some_and(|login| login.validate("monitor", "s3cret"));
                    let code = match given {
                        _ if accepted || !broker.needs_login => ConnectReturnCode::Success,
                        Some(_) => ConnectReturnCode::BadUserNamePassword,
                        None => ConnectReturnCode::NotAuthorized,
                    };
                    let _ = conn.send(Packet::ConnAck(ConnAck::new(code, false))).await;
                }
                Packet::Subscribe(subscribe) => {
                    let granted = vec![SubscribeReasonCode::Success(QoS::AtMostOnce)];
                    let topic = subscribe.filters[0].path.clone();
                    let _ = conn
                        .send(Packet::Publish(Publish::new(
                            &topic,
                            QoS::AtMostOnce,
                            "retained",
                        )))
                        .await;
                    let _ = conn
                        .send(Packet::SubAck(SubAck::new(subscribe.pkid, granted)))
                        .await;
                    let _ = conn
                        .send(Packet::Publish(Publish::new(
                            &topic,
                            QoS::AtMostOnce,
                            vec![b'x'; MAX_PACKET * 2],
                        )))
                        .await;
                }
                Packet::Publish(message) if !broker.drops_messages => {
                    let _ = conn.send(Packet::Publish(message)).await;
                }
                Packet::Disconnect => return,
                _ => {}
            }
        }
    }

    fn check(address: SocketAddr, broker: Broker) -> Check {
        let mut check = Check::new("broker", CheckKind::Mqtt, &address.to_string());
        check.insecure = Some(true);
        if broker.tls {
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
    async fn it_connects_and_times_a_test_message_in_the_clear_and_over_tls() {
        for tls in [false, true] {
            let broker = Broker { tls, ..OPEN };
            let (address, _) = fake(broker).await;
            let mut mqtt = check(address, broker);
            let result = run_signed_in(&mqtt, None).await;
            assert_eq!(result["up"], 1, "tls {tls}: {result}");
            assert!(result.get("round_trip_secs").is_none(), "{result}");
            assert_eq!(result["tls_secs"].is_f64(), tls, "{result}");
            assert_eq!(result["cert_days_left"].is_i64(), tls, "{result}");

            mqtt.topic = Some("monitoring/maxnines".to_string());
            let result = run_signed_in(&mqtt, None).await;
            assert_eq!(result["up"], 1, "tls {tls}: {result}");
            assert!(result["round_trip_secs"].is_f64(), "tls {tls}: {result}");
        }
    }

    #[tokio::test]
    async fn it_signs_in_and_never_sends_a_password_elsewhere_without_tls() {
        let broker = Broker {
            tls: true,
            needs_login: true,
            ..OPEN
        };
        let (address, leaked) = fake(broker).await;
        let mut mqtt = check(address, broker);
        mqtt.topic = Some("monitoring/maxnines".to_string());
        let result = run_signed_in(&mqtt, Some(&login("s3cret"))).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["signed_in"], true, "{result}");
        assert!(result["round_trip_secs"].is_f64(), "{result}");

        let result = run_signed_in(&mqtt, Some(&login("guess"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["signed_in"], false, "{result}");
        assert!(!result.to_string().contains("guess"), "{result}");

        // Without a login, a broker that needs one is up, unless there's a message
        // to send.
        let result = run_signed_in(&mqtt, None).await;
        assert_eq!(result["up"], 0, "{result}");
        mqtt.topic = None;
        let result = run_signed_in(&mqtt, None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert!(!leaked.load(Ordering::Relaxed));

        // The fake's address is this host, so one elsewhere is made up here.
        let mut elsewhere = Check::new("broker", CheckKind::Mqtt, "192.0.2.1:1883");
        elsewhere.timeout = Some(Duration::from_secs(1));
        let result = run_signed_in(&elsewhere, Some(&login("s3cret"))).await;
        assert_eq!(result["error"], NO_TLS, "{result}");
        assert!(result.get("connect_secs").is_none(), "{result}");
    }

    #[tokio::test]
    async fn a_message_that_never_comes_back_is_down_before_the_check_times_out() {
        let broker = Broker {
            drops_messages: true,
            ..OPEN
        };
        let (address, _) = fake(broker).await;
        let mut mqtt = check(address, broker);
        mqtt.topic = Some("monitoring/maxnines".to_string());
        mqtt.timeout = Some(Duration::from_secs(1));
        let result = run_signed_in(&mqtt, None).await;
        assert_eq!(result["up"], 0, "{result}");
        let error = result["error"].as_str().unwrap();
        assert!(
            error.starts_with("the test message didn't come back"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_bad_certificate_is_down_unless_it_is_not_minded() {
        let broker = Broker { tls: true, ..OPEN };
        let (address, _) = fake(broker).await;
        let mut strict = check(address, broker);
        strict.insecure = None;
        let result = run_signed_in(&strict, None).await;
        assert_eq!(result["up"], 0, "{result}");
        assert!(result["cert_days_left"].is_i64(), "{result}");
    }

    #[tokio::test]
    async fn something_else_is_not_taken_for_mqtt() {
        for answer in [
            b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
            // A subscription's answer where the connection's should be.
            vec![0x90, 0x03, 0x00, 0x01, 0x00],
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
            let result = run_signed_in(&check(address, OPEN), None).await;
            assert_eq!(result["up"], 0, "{result}");
            assert_eq!(result["error"], NOT_MQTT, "{result}");
        }
    }

    #[test]
    fn a_header_is_as_long_as_its_length_needs() {
        assert_eq!(header_length(0), 2);
        assert_eq!(header_length(127), 2);
        assert_eq!(header_length(128), 3);
        assert_eq!(header_length(16_383), 3);
        assert_eq!(header_length(16_384), 4);
        assert_eq!(header_length(2_097_152), 5);
    }
}
