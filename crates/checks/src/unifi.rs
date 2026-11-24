//! The UniFi check: it reads a UniFi console's devices through the console's own
//! Network API, the official one at `/proxy/network/integration/v1`, signing in with
//! an API key made on the console. It only ever asks, with GET.
//!
//! It asks what version of UniFi Network runs there, then for each site, or only the
//! one it's told, the devices the console has adopted and the clients connected
//! through each, and for each device that's online, its latest statistics: uptime,
//! CPU, memory, load and its uplink's rates. The server makes each device a host of
//! its own from what comes back.
//!
//! The check itself is up when the console answers and takes the key, whatever its
//! devices are doing, so a console that can't be reached is the check failing rather
//! than every device going offline.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use maxnines_protocol::{Check, CheckKind};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::time::timeout;

use crate::{
    Answer, Findings, Login, TOO_BIG, WebConnection, decompress, elapsed_secs, limit, open_web,
    report, timed_out,
};

/// Where the API is on a console, under its address.
const API: &str = "/proxy/network/integration/v1";

/// The most the API gives in one page.
const PAGE: u64 = 200;

/// Pages of anything read before giving up, which is 20,000 devices or clients.
const MAX_PAGES: u64 = 100;

const REFUSED: &str = "the console refused the API key";

#[cfg(any(test, feature = "fake-unifi"))]
pub mod fake;
const UNREADABLE: &str = "the console's answer couldn't be read";

/// A device a UniFi console has adopted, as it says it is.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    /// The console's ID for it, which stays the same through renames.
    pub id: String,
    pub mac: String,
    pub name: String,
    pub model: String,
    pub ip: String,
    pub firmware: Option<String>,
    /// Such as `ONLINE`, `OFFLINE` or `UPDATING`, as the console says.
    pub state: String,
    /// Whether a newer firmware is waiting to be put on it.
    pub firmware_updatable: bool,
    /// What it does: `gateway`, `switching` and `accessPoint`.
    pub features: Vec<String>,
    /// The site it's in, by its name.
    pub site: String,
    /// Clients connected through it now, wired or wireless.
    pub clients: u64,
    /// Its latest statistics, read while it's online.
    pub statistics: Option<Statistics>,
}

impl Device {
    pub fn is_online(&self) -> bool {
        self.state == "ONLINE"
    }
}

/// A device's latest statistics. The console leaves out what a device doesn't
/// report, so each can be missing.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statistics {
    pub uptime_sec: Option<u64>,
    pub cpu_utilization_pct: Option<f64>,
    pub memory_utilization_pct: Option<f64>,
    #[serde(rename = "loadAverage1Min")]
    pub load_average_1_min: Option<f64>,
    #[serde(rename = "loadAverage5Min")]
    pub load_average_5_min: Option<f64>,
    #[serde(rename = "loadAverage15Min")]
    pub load_average_15_min: Option<f64>,
    #[serde(default)]
    pub uplink: Uplink,
}

/// The rates of a device's connection to the one above it, in bits a second.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Uplink {
    pub rx_rate_bps: Option<u64>,
    pub tx_rate_bps: Option<u64>,
}

/// What reading a console found: the check's own result, and its devices when it
/// could read them.
pub struct Console {
    pub report: Value,
    pub devices: Option<Vec<Device>>,
}

/// Reads a console, until it's done or out of the check's time, signing in with
/// `api_key`. Always gives the check's result, and the devices only when every
/// list was read, so a console that stops answering part way never makes devices
/// look gone.
pub async fn read(check: &Check, api_key: Option<&str>) -> Console {
    let started = Instant::now();
    let mut findings = Findings::default();
    let work = read_console(check, api_key, &mut findings);
    let result = timeout(limit(check), work)
        .await
        .unwrap_or_else(|_| Err(timed_out()));
    let (result, devices) = match result {
        Ok(devices) => {
            findings.response_secs = Some(elapsed_secs(started));
            (Ok(()), Some(devices))
        }
        Err(error) => (Err(error), None),
    };
    Console {
        report: report(check, findings, result),
        devices,
    }
}

async fn read_console(
    check: &Check,
    api_key: Option<&str>,
    findings: &mut Findings,
) -> Result<Vec<Device>> {
    let api_key = api_key.context("a UniFi check needs an API key")?;
    let mut session = Session {
        check,
        login: Login::api_key(api_key)?,
        connection: None,
    };
    let info: Info = session
        .get_timed("/info", findings)
        .await?
        .context("there's no UniFi Network API at this address")?;
    findings.server_version = Some(info.application_version);

    let mut sites: Vec<Site> = session.all("/sites").await?;
    if let Some(wanted) = &check.site {
        let wanted = wanted.trim();
        sites.retain(|site| {
            site.name.eq_ignore_ascii_case(wanted)
                || site.internal_reference.eq_ignore_ascii_case(wanted)
        });
        if sites.is_empty() {
            bail!("the console has no site called {wanted:?}");
        }
    }

    let mut devices = Vec::new();
    for site in sites {
        let listed: Vec<Listed> = session.all(&format!("/sites/{}/devices", site.id)).await?;
        let clients: Vec<ClientRow> = session.all(&format!("/sites/{}/clients", site.id)).await?;
        let mut through: HashMap<String, u64> = HashMap::new();
        for client in clients {
            if let Some(device) = client.uplink_device_id {
                *through.entry(device).or_default() += 1;
            }
        }
        for row in listed {
            let mut device = Device {
                clients: through.get(&row.id).copied().unwrap_or_default(),
                id: row.id,
                mac: row.mac_address,
                name: row.name,
                model: row.model,
                ip: row.ip_address,
                firmware: row.firmware_version,
                state: row.state,
                firmware_updatable: row.firmware_updatable,
                features: row.features,
                site: site.name.clone(),
                statistics: None,
            };
            // Only an online device has statistics to give, and one the console
            // has none for yet isn't a failure of the check.
            if device.is_online() {
                let path = format!("/sites/{}/devices/{}/statistics/latest", site.id, device.id);
                device.statistics = session.get(&path).await?;
            }
            devices.push(device);
        }
    }
    Ok(devices)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Info {
    application_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Site {
    id: String,
    #[serde(default)]
    internal_reference: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Listed {
    id: String,
    #[serde(default)]
    mac_address: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    ip_address: String,
    firmware_version: Option<String>,
    #[serde(default)]
    state: String,
    #[serde(default)]
    firmware_updatable: bool,
    #[serde(default)]
    features: Vec<String>,
}

/// A client, of which only the device it connects through counts. VPN clients
/// have none.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRow {
    uplink_device_id: Option<String>,
}

/// One page of a list.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page<T> {
    data: Vec<T>,
    total_count: u64,
}

/// Requests to one console, on one connection while it stays open.
struct Session<'a> {
    check: &'a Check,
    login: Login,
    connection: Option<WebConnection>,
}

impl Session<'_> {
    /// Asks for `path` under the API, giving nothing for one the console says
    /// isn't there.
    async fn get<T: DeserializeOwned + Send + 'static>(&mut self, path: &str) -> Result<Option<T>> {
        self.get_timed(path, &mut Findings::default()).await
    }

    /// As [`get`](Self::get), timing each stage in `findings`.
    async fn get_timed<T: DeserializeOwned + Send + 'static>(
        &mut self,
        path: &str,
        findings: &mut Findings,
    ) -> Result<Option<T>> {
        let address = format!("{}{API}{path}", self.check.target);
        let mut request = Check::new(&self.check.name, CheckKind::Http, &address);
        request.insecure = self.check.insecure;
        let mut connection = match self.connection.take() {
            Some(mut open) => {
                if open.is_ready().await {
                    open
                } else {
                    open_web(&request, findings).await?
                }
            }
            None => open_web(&request, findings).await?,
        };
        let answer = connection
            .send(&request, findings, Some(&self.login))
            .await?;
        self.connection = Some(connection);
        match answer.status {
            200..=299 => read_json(answer).await.map(Some),
            401 | 403 => bail!(REFUSED),
            404 => Ok(None),
            status => bail!("the console returned status {status}"),
        }
    }

    /// Every item of a list, a page at a time.
    async fn all<T: DeserializeOwned + Send + 'static>(&mut self, path: &str) -> Result<Vec<T>> {
        let mut items = Vec::new();
        for _ in 0..MAX_PAGES {
            let offset = items.len();
            let page: Page<T> = self
                .get(&format!("{path}?offset={offset}&limit={PAGE}"))
                .await?
                .ok_or_else(|| anyhow!("the console has no {path} to list"))?;
            let got = page.data.len();
            items.extend(page.data);
            if got == 0 || items.len() as u64 >= page.total_count {
                return Ok(items);
            }
        }
        bail!(
            "the console listed more than {} of {path}",
            MAX_PAGES * PAGE
        )
    }
}

/// An answer's JSON, unpacked if it came packed. Done off the task's thread, as a
/// big list takes real time to read.
async fn read_json<T: DeserializeOwned + Send + 'static>(answer: Answer) -> Result<T> {
    anyhow::ensure!(!answer.cut, TOO_BIG);
    tokio::task::spawn_blocking(move || {
        let body = if answer.compressed {
            let (body, cut) = decompress(&answer.body).context(UNREADABLE)?;
            anyhow::ensure!(!cut, TOO_BIG);
            body
        } else {
            answer.body
        };
        serde_json::from_slice(&body).map_err(|_| anyhow!(UNREADABLE))
    })
    .await
    .map_err(|_| anyhow!(UNREADABLE))?
}

#[cfg(test)]
mod tests {
    use super::fake::{ACCESS_POINT, FakeConsole, GATEWAY, KEY, SWITCH};
    use super::*;

    fn check(console: &FakeConsole) -> Check {
        let mut check = Check::new("UniFi", CheckKind::Unifi, &console.target());
        check.insecure = Some(true);
        check
    }

    #[tokio::test]
    async fn every_device_is_read_with_its_statistics_and_clients() {
        let console = FakeConsole::start().await;
        let read = read(&check(&console), Some(KEY)).await;

        assert_eq!(read.report["up"], 1, "{}", read.report);
        assert_eq!(read.report["server_version"], "9.1.120");
        assert!(read.report["response_secs"].as_f64().is_some());
        let devices = read.devices.unwrap();
        assert_eq!(devices.len(), 3, "every page of devices is read");

        let gateway = &devices[0];
        assert_eq!(gateway.id, GATEWAY);
        assert_eq!(gateway.name, "Dream Machine");
        assert_eq!(gateway.site, "Default");
        assert_eq!(gateway.clients, 1);
        let statistics = gateway.statistics.as_ref().unwrap();
        assert_eq!(statistics.uptime_sec, Some(86_400));
        assert_eq!(statistics.cpu_utilization_pct, Some(12.5));
        assert_eq!(statistics.memory_utilization_pct, Some(61.0));
        assert_eq!(statistics.load_average_15_min, Some(0.125));
        assert_eq!(statistics.uplink.rx_rate_bps, Some(16_000));

        let switch = &devices[1];
        assert_eq!(switch.id, SWITCH);
        assert_eq!(
            switch.clients, 2,
            "clients are counted by the device they're on"
        );
        assert!(switch.firmware_updatable);
        assert_eq!(switch.statistics, None, "none yet isn't a failure");

        let access_point = &devices[2];
        assert_eq!(access_point.id, ACCESS_POINT);
        assert!(!access_point.is_online());
        assert_eq!(access_point.statistics, None);

        let asked = console.asked();
        assert!(asked.iter().all(|(_, key)| key.as_deref() == Some(KEY)));
        let statistics: Vec<&String> = asked
            .iter()
            .map(|(path, _)| path)
            .filter(|path| path.ends_with("/statistics/latest"))
            .collect();
        assert_eq!(
            statistics.len(),
            2,
            "an offline device isn't asked: {statistics:?}"
        );
    }

    #[tokio::test]
    async fn a_refused_key_fails_the_check_and_gives_no_devices() {
        let console = FakeConsole::start().await;
        let read = read(&check(&console), Some("wrong")).await;
        assert_eq!(read.report["up"], 0);
        assert_eq!(read.report["error"], REFUSED);
        assert!(read.devices.is_none());
        assert!(
            !read.report.to_string().contains("wrong"),
            "the key is never told"
        );

        let read = super::read(&check(&console), None).await;
        assert_eq!(read.report["up"], 0);
        assert!(read.devices.is_none());
    }

    #[tokio::test]
    async fn a_console_with_a_certificate_of_its_own_needs_insecure() {
        let console = FakeConsole::start().await;
        let mut strict = check(&console);
        strict.insecure = None;
        let read = read(&strict, Some(KEY)).await;
        assert_eq!(read.report["up"], 0);
        assert!(read.devices.is_none());
        assert_eq!(read.report["cert_valid"], false);
        assert!(console.asked().is_empty(), "the key is never sent to it");
    }

    #[tokio::test]
    async fn a_closed_port_fails_the_check() {
        // Port 0 is never listening.
        let closed = Check::new("UniFi", CheckKind::Unifi, "https://127.0.0.1:0");
        let read = read(&closed, Some(KEY)).await;
        assert_eq!(read.report["up"], 0);
        assert!(read.devices.is_none());
    }

    #[tokio::test]
    async fn a_site_can_be_chosen_by_either_of_its_names() {
        let console = FakeConsole::start().await;
        for name in ["default", "Default"] {
            let mut one = check(&console);
            one.site = Some(name.to_string());
            let read = read(&one, Some(KEY)).await;
            assert_eq!(read.devices.unwrap().len(), 3, "{name}");
        }
        let mut missing = check(&console);
        missing.site = Some("Lake house".to_string());
        let read = read(&missing, Some(KEY)).await;
        assert_eq!(read.report["up"], 0);
        assert_eq!(
            read.report["error"],
            "the console has no site called \"Lake house\""
        );
    }
}
