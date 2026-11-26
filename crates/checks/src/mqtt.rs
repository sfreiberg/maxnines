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

use anyhow::{Result, anyhow, bail, ensure};
use bytes::BytesMut;
use maxnines_protocol::Check;
use rumqttc::mqttbytes::v4::{ConnAck, ConnectReturnCode, Packet, SubscribeReasonCode};
use rumqttc::mqttbytes::{Error as PacketError, QoS, check as check_frame};
use rumqttc::{Connect, Publish, Subscribe};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout_at;

use crate::sign_in::{
    Credentials, Password, TLS_NEEDED_ELSEWHERE, is_loopback, username_and_password,
};
use crate::{
    Findings, certificate_verdict, connect, elapsed_secs, host_and_port, limit, resolve, secure,
};

const NOT_MQTT: &str = "it didn't answer as an MQTT broker does";

/// Far more than anything a broker answers the check with. A message someone else
/// sends to the test topic can be bigger, and is skipped without being kept.
const MAX_PACKET: usize = 64 * 1024;
/// How long the broker waits to hear from the check, which never pings, before
/// giving up on it. A broker gives it half as long again, which is far longer than
/// a check's minute at most, so the broker never hangs up while the check waits.
const KEEP_ALIVE_SECS: u16 = 60;
/// What's left of the check's time when the test message is given up on, so that
/// it's reported as never coming back rather than the whole check timing out.
const MESSAGE_MARGIN: Duration = Duration::from_millis(250);
/// How many other messages on the test topic are passed over waiting for the
/// check's own.
const MAX_OTHER_MESSAGES: usize = 1000;

pub(crate) async fn check_mqtt(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let deadline = Instant::now() + limit(check).saturating_sub(MESSAGE_MARGIN);
    // MQTT lets a client give a username alone, but never a password alone.
    let login = username_and_password(credentials, Password::Optional)?;
    let (host, port) = host_and_port(&check.target)?;
    let tls = check.tls == Some(true);
    if login.is_some_and(|(_, password)| !password.is_empty()) {
        ensure!(tls || is_loopback(&host), TLS_NEEDED_ELSEWHERE);
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
        // The ID only has to be unique for as long as the check is connected. Up to
        // 23 letters and digits is all a broker has to take, so it has no hyphen.
        let client_id = format!("maxnines{:012x}", rand::random::<u64>() >> 16);
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
        // A broker that turns the check down for something else hasn't said
        // anything about the login.
        if login.is_some() && (needs_login || answer.code == ConnectReturnCode::Success) {
            findings.signed_in = Some(answer.code == ConnectReturnCode::Success);
        }
        match answer.code {
            ConnectReturnCode::Success => {}
            _ if needs_login && login.is_some_and(|(_, password)| password.is_empty()) => {
                bail!(
                    "it didn't let the account in with its username alone, so it needs a password"
                )
            }
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
            // Whatever connecting took comes out of the time the message gets, so
            // how long that was is said, as well as the likeliest reason.
            let left = deadline.saturating_duration_since(Instant::now());
            let round_trip = timeout_at(deadline.into(), self.round_trip(topic))
                .await
                .map_err(|_| {
                    anyhow!(
                        "the test message didn't come back in the {:.1} seconds left of the \
                         check's time, as it doesn't when the account isn't allowed to send \
                         to the topic or read it",
                        left.as_secs_f64()
                    )
                })??;
            findings.round_trip_secs = Some(round_trip);
        }
        Ok(())
    }

    /// Subscribes to `topic`, then sends a message there that no one else would and
    /// waits for it, giving how long that took from sending it, in seconds. Both are
    /// at most once, so the broker keeps nothing for later, and it isn't retained,
    /// so nothing's left on the topic.
    async fn round_trip(&mut self, topic: &str) -> Result<f64> {
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
        let sent = Instant::now();
        self.send(Packet::Publish(Publish::new(
            topic,
            QoS::AtMostOnce,
            payload.as_bytes(),
        )))
        .await?;
        for _ in 0..MAX_OTHER_MESSAGES {
            match self.packet().await? {
                Packet::Publish(message) if message.payload == payload.as_bytes() => {
                    return Ok(elapsed_secs(sent));
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
                    Err(PacketError::PayloadSizeLimitExceeded(_)) => {
                        // Only a message can be this big. Without a limit, its header
                        // says how long it is in all, or how much of it is still to
                        // come.
                        ensure!(
                            self.buffer.first().is_some_and(|byte| byte >> 4 == 3),
                            NOT_MQTT
                        );
                        skipping = match check_frame(self.buffer.iter(), usize::MAX) {
                            Ok(header) => header.frame_length(),
                            Err(PacketError::InsufficientBytes(missing)) => {
                                self.buffer.len() + missing
                            }
                            Err(_) => bail!(NOT_MQTT),
                        };
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
        /// Turns everyone away as unavailable.
        unavailable: bool,
    }

    const OPEN: Broker = Broker {
        tls: false,
        needs_login: false,
        drops_messages: false,
        unavailable: false,
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
                        _ if broker.unavailable => ConnectReturnCode::ServiceUnavailable,
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

        // No password was sent, so it isn't blamed.
        let result = run_signed_in(&mqtt, Some(&login(""))).await;
        assert_eq!(result["signed_in"], false, "{result}");
        let error = result["error"].as_str().unwrap();
        assert!(error.contains("username alone"), "{error}");

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
        assert_eq!(result["error"], TLS_NEEDED_ELSEWHERE, "{result}");
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
            error.starts_with("the test message didn't come back in the 0."),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_unavailable_broker_says_nothing_about_the_login() {
        let broker = Broker {
            unavailable: true,
            ..OPEN
        };
        let (address, _) = fake(broker).await;
        let result = run_signed_in(&check(address, broker), Some(&login("s3cret"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(
            result["error"], "it isn't taking connections now",
            "{result}"
        );
        assert!(result.get("signed_in").is_none(), "{result}");
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

    /// A broker may write a length in more bytes than it needs, which has to be
    /// skipped by what it says, not by how long it would be written shortest.
    #[tokio::test]
    async fn a_message_too_big_to_keep_is_skipped_however_its_length_is_written() {
        let (mut broker, client) = tokio::io::duplex(1 << 20);
        // 70,000 bytes, which takes 3 bytes, in 4.
        let mut bytes = vec![0x30, 0xf0, 0xa2, 0x84, 0x00];
        bytes.extend([0x00, 0x01, b't']);
        bytes.resize(5 + 70_000, b'x');
        // Then the broker's answer to connecting, which has to be read whole.
        bytes.extend([0x20, 0x02, 0x00, 0x00]);
        broker.write_all(&bytes).await.unwrap();
        let mut mqtt = Mqtt::new(client);
        assert!(matches!(mqtt.packet().await.unwrap(), Packet::ConnAck(_)));
    }
}
