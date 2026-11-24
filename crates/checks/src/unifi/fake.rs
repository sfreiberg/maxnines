//! A UniFi console of its own, for tests: it answers the Network API's GETs as
//! Ubiquiti's reference says a console does, over HTTPS with a certificate of its
//! own making for `localhost`, as a console's own is, and in pages smaller than
//! asked for, so paging is tested. What it lists can be changed while it runs.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::API;

/// The key it takes. Any other is refused.
pub const KEY: &str = "test-key-not-real";
pub const SITE: &str = "88f7af54-98f8-306a-a1c7-c9349722b1f6";
pub const GATEWAY: &str = "4d8c3a1e-0000-4000-8000-000000000001";
pub const SWITCH: &str = "4d8c3a1e-0000-4000-8000-000000000002";
pub const ACCESS_POINT: &str = "4d8c3a1e-0000-4000-8000-000000000003";

struct State {
    devices: Vec<Value>,
    /// Clients, each by the device it connects through, or none for VPN.
    clients: Vec<Option<String>>,
    /// Each path asked for, in order, with the key it was sent.
    asked: Vec<(String, Option<String>)>,
}

pub struct FakeConsole {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
}

/// A device as the list of devices has it.
pub fn device(id: &str, name: &str, state: &str) -> Value {
    json!({
        "id": id, "macAddress": format!("74:ac:b9:00:00:{}", &id[id.len() - 2..]),
        "name": name, "model": "UDM Pro", "ipAddress": "192.168.1.1",
        "firmwareVersion": "4.1.13", "state": state, "firmwareUpdatable": false,
        "features": ["gateway"], "interfaces": ["ports"], "supported": true,
    })
}

impl FakeConsole {
    /// Starts one with a Dream Machine with one client, a switch with two and a
    /// firmware update waiting, which has no statistics yet, an access point
    /// that's offline, and a VPN client.
    pub async fn start() -> Self {
        let mut switch = device(SWITCH, "Garage switch", "ONLINE");
        switch["features"] = json!(["switching"]);
        switch["firmwareUpdatable"] = json!(true);
        let state = Arc::new(Mutex::new(State {
            devices: vec![
                device(GATEWAY, "Dream Machine", "ONLINE"),
                switch,
                device(ACCESS_POINT, "Attic AP", "OFFLINE"),
            ],
            clients: vec![
                Some(SWITCH.to_string()),
                Some(SWITCH.to_string()),
                Some(GATEWAY.to_string()),
                None,
            ],
            asked: Vec::new(),
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = acceptor();
        let serving = state.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, state) = (acceptor.clone(), serving.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(socket).await {
                        serve(stream, &state).await;
                    }
                });
            }
        });
        Self { address, state }
    }

    /// Its address, as a check's target.
    pub fn target(&self) -> String {
        format!("https://localhost:{}", self.address.port())
    }

    pub fn set_devices(&self, devices: Vec<Value>) {
        self.state().devices = devices;
    }

    pub fn asked(&self) -> Vec<(String, Option<String>)> {
        self.state().asked.clone()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn acceptor() -> TlsAcceptor {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

/// Answers requests on one connection, kept open between them, until it closes.
async fn serve<S>(stream: S, state: &Mutex<State>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    loop {
        let mut head = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => return,
                Ok(_) if line == "\r\n" => break,
                Ok(_) => head.push_str(&line),
            }
        }
        let mut lines = head.lines();
        let mut first = lines.next().unwrap_or_default().split(' ');
        let (method, path) = (
            first.next().unwrap_or_default(),
            first.next().unwrap_or_default(),
        );
        assert_eq!(method, "GET", "a UniFi check only ever asks");
        let key = lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-api-key")
                .then(|| value.trim().to_string())
        });
        let (status, body) = {
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            state.asked.push((path.to_string(), key.clone()));
            answer(&state, path, key.as_deref())
        };
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if reader
            .get_mut()
            .write_all(response.as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

/// One page of `items`, from `offset` and at most two long, whatever's asked.
fn page(items: &[Value], query: &str) -> Value {
    let number = |name: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .and_then(|value| value.parse::<usize>().ok())
    };
    let offset = number("offset").unwrap_or(0);
    let limit = number("limit").unwrap_or(25).min(2);
    let data: Vec<Value> = items.iter().skip(offset).take(limit).cloned().collect();
    json!({
        "offset": offset, "limit": limit, "count": data.len(),
        "totalCount": items.len(), "data": data,
    })
}

fn answer(state: &State, path: &str, key: Option<&str>) -> (u16, Value) {
    if key != Some(KEY) {
        return (
            401,
            json!({
                "statusCode": 401, "statusName": "UNAUTHORIZED",
                "code": "api.authentication.missing-credentials",
                "message": "Missing credentials",
            }),
        );
    }
    let not_found = json!({ "statusCode": 404, "statusName": "NOT_FOUND" });
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let Some(rest) = path.strip_prefix(API) else {
        return (404, not_found);
    };
    let site = format!("/sites/{SITE}");
    if rest == "/info" {
        return (200, json!({ "applicationVersion": "9.1.120" }));
    }
    if rest == "/sites" {
        let sites = [json!({ "id": SITE, "internalReference": "default", "name": "Default" })];
        return (200, page(&sites, query));
    }
    let Some(rest) = rest.strip_prefix(&site) else {
        return (404, not_found);
    };
    match rest {
        "/devices" => (200, page(&state.devices, query)),
        "/clients" => {
            let clients: Vec<Value> = state
                .clients
                .iter()
                .enumerate()
                .map(|(index, through)| match through {
                    Some(device) => json!({
                        "id": format!("c{index}"), "name": "phone", "type": "WIRELESS",
                        "macAddress": "00:00:00:00:00:01", "uplinkDeviceId": device,
                        "access": { "type": "DEFAULT" },
                    }),
                    None => json!({
                        "id": format!("c{index}"), "name": "laptop", "type": "VPN",
                        "access": { "type": "DEFAULT" },
                    }),
                })
                .collect();
            (200, page(&clients, query))
        }
        // Only the Dream Machine has statistics: an online device the console has
        // none for yet is answered as not there.
        _ if rest == format!("/devices/{GATEWAY}/statistics/latest") => (
            200,
            json!({
                "uptimeSec": 86_400, "lastHeartbeatAt": "2026-11-24T10:00:00Z",
                "nextHeartbeatAt": "2026-11-24T10:00:10Z",
                "loadAverage1Min": 0.5, "loadAverage5Min": 0.25, "loadAverage15Min": 0.125,
                "cpuUtilizationPct": 12.5, "memoryUtilizationPct": 61.0,
                "uplink": { "txRateBps": 8000, "rxRateBps": 16000 },
                "interfaces": {},
            }),
        ),
        _ => (404, not_found),
    }
}
