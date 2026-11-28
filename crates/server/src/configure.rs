//! Sets the address, port and HTTPS in the config file, for the Windows installer
//! and its Modify button, and adds the first administrator. Only the values it
//! sets change: comments, registration rules and anything else in the file are
//! kept as they were.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use hcl::edit::expr::Expression;
use hcl::edit::structure::Body;
use maxnines_protocol::config_file::{self, Address, block, path_text, set};

use crate::config::Config;

/// The account the Windows service runs as, `NT SERVICE\MaxNinesServer`, which
/// Windows makes from the service's name. The installer gives it the data folder
/// and its registry key, before the service exists.
pub const SERVICE_ACCOUNT_SID: &str =
    "S-1-5-80-4185855007-1177842744-2721872280-2574161336-224657692";

/// The config written when there isn't one yet.
const TEMPLATE: &str = include_str!("../../../packaging/windows/server.hcl");

/// How the server serves HTTPS, as the installer asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Https {
    /// Plain HTTP, on a trusted network or behind a proxy that handles HTTPS
    None,
    /// Certificates from Let's Encrypt, which has to reach this server on port 443
    Automatic,
    /// A certificate and key from files
    Files,
}

impl Https {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Automatic => "automatic",
            Self::Files => "files",
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Settings {
    pub address: String,
    pub port: u16,
    pub https: Option<Https>,
    pub acme_email: Option<String>,
    pub certificate_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

/// The config file's new text: `existing`, or the template when there's no file
/// yet, with the settings applied.
pub fn edit(existing: Option<&str>, folder: &Path, settings: &Settings) -> Result<String> {
    let address = Address::parse(&settings.address)?;
    let https = settings.https.unwrap_or(Https::None);
    ensure!(settings.port > 0, "the port can't be 0");
    if https != Https::None {
        ensure!(
            address.is_secure(),
            "with HTTPS, the server's address starts with https://"
        );
    }

    let mut body: Body = existing
        .unwrap_or(TEMPLATE)
        .parse()
        .context("reading the config file")?;
    if existing.is_none() {
        // Relative paths would mean wherever a command was run from.
        let metrics = block(&mut body, "", "metrics");
        set(
            metrics,
            "  ",
            "path",
            path_text(&folder.join("metrics.duckdb"))?,
        );
        let sqlite = folder.join("maxnines.sqlite");
        let sqlite = path_text(&sqlite)?.replace('\\', "/");
        let database = block(&mut body, "", "database");
        set(database, "  ", "url", format!("sqlite://{sqlite}?mode=rwc"));
    }

    // Only the port changes, so listening on one address of several stays.
    let ip = body
        .get_attribute("listen")
        .and_then(|listen| listen.value.as_str())
        .and_then(|listen| listen.parse::<SocketAddr>().ok())
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |listen| listen.ip());
    set(
        &mut body,
        "",
        "listen",
        SocketAddr::new(ip, settings.port).to_string(),
    );
    set(&mut body, "", "public_url", address.agent_url());

    match https {
        Https::None => {
            body.remove_blocks("tls");
        }
        Https::Files => {
            let (Some(certificate), Some(key)) = (&settings.certificate_file, &settings.key_file)
            else {
                bail!("HTTPS from files needs the certificate file and the key file");
            };
            let tls = block(&mut body, "", "tls");
            tls.remove_blocks("acme");
            set(tls, "  ", "certificate_file", path_text(certificate)?);
            set(tls, "  ", "key_file", path_text(key)?);
        }
        Https::Automatic => {
            let tls = block(&mut body, "", "tls");
            tls.remove_attribute("certificate_file");
            tls.remove_attribute("key_file");
            let acme = block(tls, "  ", "acme");
            set(
                acme,
                "    ",
                "domains",
                Expression::from(vec![address.host()]),
            );
            match settings.acme_email.as_deref().map(str::trim) {
                Some(email) if !email.is_empty() => set(acme, "    ", "email", email),
                _ => {
                    acme.remove_attribute("email");
                }
            }
            if !acme.has_attribute("cache_dir") {
                set(acme, "    ", "cache_dir", path_text(&folder.join("acme"))?);
            }
        }
    }

    let text = body.to_string();
    Config::parse(&text).context("checking the new config")?;
    Ok(text)
}

/// Writes the config, returning it as the server will read it. `prepare` is done
/// to the new file before it takes the old one's place, such as setting who can
/// open it.
pub fn write(
    config: &Path,
    settings: &Settings,
    prepare: impl FnOnce(&Path) -> Result<()>,
) -> Result<Config> {
    if settings.https == Some(Https::Files) {
        for file in [&settings.certificate_file, &settings.key_file]
            .into_iter()
            .flatten()
        {
            ensure!(file.is_file(), "there's no file at {}", file.display());
        }
    }
    let (path, folder) = config_file::locate(config)?;
    let existing = config_file::read(&path)?;
    let text = edit(existing.as_deref(), &folder, settings)?;
    config_file::replace_prepared(&path, &text, prepare)?;
    println!("Saved the settings in {}.", path.display());
    Config::parse(&text)
}

/// The settings as the installer shows them in Modify, under its names for them,
/// from the config the server runs with.
pub fn installer_settings(config: &Config) -> Vec<(&'static str, String)> {
    let tls = config.tls.as_ref();
    let acme = tls.and_then(|tls| tls.acme.as_ref());
    let https = match (tls, acme) {
        (None, _) => Https::None,
        (Some(_), Some(_)) => Https::Automatic,
        (Some(_), None) => Https::Files,
    };
    let text = |path: Option<&PathBuf>| {
        path.and_then(|path| path.to_str())
            .unwrap_or_default()
            .to_string()
    };
    vec![
        (
            "SERVER_ADDRESS",
            config_file::browser_address(&config.audience()),
        ),
        ("PORT", config.listen.port().to_string()),
        ("HTTPS", https.as_str().to_string()),
        (
            "ACME_EMAIL",
            acme.and_then(|acme| acme.email.clone()).unwrap_or_default(),
        ),
        (
            "CERTIFICATE_FILE",
            text(tls.and_then(|tls| tls.certificate_file.as_ref())),
        ),
        ("KEY_FILE", text(tls.and_then(|tls| tls.key_file.as_ref()))),
    ]
}

/// Lets the service's account read a file the installer was given, such as the
/// certificate and key, wherever they are. The rest of who can read it stays.
#[cfg(windows)]
pub fn let_service_read(path: &Path) -> Result<()> {
    icacls(path, &["/grant", &format!("*{SERVICE_ACCOUNT_SID}:(R)")])
}

/// Only Windows and administrators can change the config, and the service can
/// only read it, so a server that's been taken over can't choose what the
/// installer, which runs as Windows itself, does next.
#[cfg(windows)]
pub fn protect_config(path: &Path) -> Result<()> {
    icacls(
        path,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
            &format!("*{SERVICE_ACCOUNT_SID}:(R)"),
        ],
    )
}

/// Windows' own icacls, which sets who can open a file. Only whether it worked
/// is read from it, as what it prints is in the system's language.
#[cfg(windows)]
fn icacls(path: &Path, arguments: &[&str]) -> Result<()> {
    let windows = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let icacls = Path::new(&windows).join("System32").join("icacls.exe");
    let output = std::process::Command::new(&icacls)
        .arg(path)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("running {}", icacls.display()))?;
    ensure!(
        output.status.success(),
        "icacls couldn't change {}: {} {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim()
    );
    Ok(())
}

/// The installer's settings, in its names for them, as [`installer_settings`]
/// gives them.
pub const INSTALLER_SETTINGS: [&str; 6] = [
    "SERVER_ADDRESS",
    "PORT",
    "HTTPS",
    "ACME_EMAIL",
    "CERTIFICATE_FILE",
    "KEY_FILE",
];

/// What to set, from what the installer was given. Modify shows what it was
/// given last time, which may since have been changed in the config by hand, so
/// a setting given as it was then keeps what the config says now.
pub fn keep_hand_edits(
    given: &[(&'static str, String)],
    remembered: &BTreeMap<String, String>,
    current: &[(&'static str, String)],
) -> Vec<(&'static str, String)> {
    given
        .iter()
        .map(|(name, value)| {
            let unchanged = remembered.get(*name).map_or("", String::as_str) == value.trim();
            let now = current.iter().find(|(other, _)| other == name);
            match now {
                Some((_, now)) if unchanged => (*name, now.clone()),
                _ => (*name, value.trim().to_string()),
            }
        })
        .collect()
}

impl Settings {
    /// From the installer's settings, with an empty one left out.
    pub fn from_installer(values: &[(&'static str, String)]) -> Result<Self> {
        let get = |name: &str| {
            values
                .iter()
                .find(|(other, _)| *other == name)
                .map(|(_, value)| value.as_str())
                .filter(|value| !value.is_empty())
        };
        let port = get("PORT").context("the port is missing")?;
        let https = get("HTTPS").unwrap_or("none");
        Ok(Self {
            address: get("SERVER_ADDRESS")
                .context("the address is missing")?
                .to_string(),
            port: port
                .parse()
                .map_err(|_| anyhow::anyhow!("{port:?} isn't a port"))?,
            https: Some(
                <Https as clap::ValueEnum>::from_str(https, true).map_err(|_| {
                    anyhow::anyhow!("HTTPS is none, automatic or files, not {https:?}")
                })?,
            ),
            acme_email: get("ACME_EMAIL").map(String::from),
            certificate_file: get("CERTIFICATE_FILE").map(PathBuf::from),
            key_file: get("KEY_FILE").map(PathBuf::from),
        })
    }
}

/// A shortcut that opens `url`, which Windows opens in the browser.
pub fn shortcut(url: &str) -> String {
    format!("[InternetShortcut]\r\nURL={url}\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(address: &str, port: u16, https: Https) -> Settings {
        Settings {
            address: address.to_string(),
            port,
            https: Some(https),
            ..Settings::default()
        }
    }

    #[test]
    fn a_new_config_comes_from_the_template_with_absolute_paths() {
        let folder = Path::new("/data/MaxNines/Server");
        let text = edit(
            None,
            folder,
            &settings("http://MAXNINES:9000", 9000, Https::None),
        )
        .unwrap();

        let config = Config::parse(&text).unwrap();
        assert_eq!(config.listen, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(config.audience(), "ws://MAXNINES:9000/ws");
        assert_eq!(
            config.metrics.path(),
            Some(folder.join("metrics.duckdb").as_path())
        );
        assert_eq!(
            config.database.url.as_deref(),
            Some("sqlite:///data/MaxNines/Server/maxnines.sqlite?mode=rwc")
        );
        assert!(config.tls.is_none());
        assert!(text.starts_with("# The MaxNines server's settings"));
    }

    #[test]
    fn automatic_https_gets_a_certificate_for_the_address() {
        let mut settings = settings("https://monitor.example.com", 443, Https::Automatic);
        settings.acme_email = Some("you@example.com".to_string());
        let text = edit(None, Path::new("/data"), &settings).unwrap();

        let config = Config::parse(&text).unwrap();
        assert_eq!(config.audience(), "wss://monitor.example.com/ws");
        let acme = config.tls.unwrap().acme.unwrap();
        assert_eq!(acme.domains, ["monitor.example.com"]);
        assert_eq!(acme.email.as_deref(), Some("you@example.com"));
        assert_eq!(acme.cache_dir, Path::new("/data/acme"));
        assert!(text.contains(
            "\ntls {\n  acme {\n    domains = [\"monitor.example.com\"]\n    email = \"you@example.com\"\n"
        ));
    }

    #[test]
    fn switching_https_keeps_what_was_added_by_hand() {
        let existing = r#"listen = "10.0.0.5:9000" # the LAN side
public_url = "ws://old:9000/ws"

tls {
  certificate_file = "old.crt"
  key_file = "old.key"
  ca_file = "private-ca.pem"
}

metrics "duckdb" {
  path = "D:/metrics.duckdb"
}

registration {
  rule "office" {
    action = "approve"
    source_cidrs = ["10.0.0.0/8"]
    token_file = "office.token"
  }
}
"#;
        let mut files = settings("https://m.example.com:8443", 8443, Https::Files);
        files.certificate_file = Some(PathBuf::from("new.crt"));
        files.key_file = Some(PathBuf::from("new.key"));
        let text = edit(Some(existing), Path::new("/ignored"), &files).unwrap();

        assert_eq!(
            text,
            existing
                .replace("10.0.0.5:9000", "10.0.0.5:8443")
                .replace("ws://old:9000/ws", "wss://m.example.com:8443/ws")
                .replace("old.crt", "new.crt")
                .replace("old.key", "new.key")
        );

        let automatic = settings("https://m.example.com", 443, Https::Automatic);
        let text = edit(Some(&text), Path::new("/data"), &automatic).unwrap();
        let config = Config::parse(&text).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.certificate_file, None);
        assert_eq!(tls.ca_file.as_deref(), Some(Path::new("private-ca.pem")));
        assert_eq!(tls.acme.unwrap().email, None);
        assert!(text.contains("rule \"office\""));

        let none = settings("http://m.example.com:9000", 9000, Https::None);
        let text = edit(Some(&text), Path::new("/data"), &none).unwrap();
        assert!(Config::parse(&text).unwrap().tls.is_none());
        assert!(!text.contains("tls"));
    }

    #[test]
    fn https_needs_an_https_address_and_its_files() {
        for https in [Https::Automatic, Https::Files] {
            let error = edit(
                None,
                Path::new("/data"),
                &settings("http://m.example.com", 80, https),
            )
            .unwrap_err();
            assert!(error.to_string().contains("https://"), "{error}");
        }
        let error = edit(
            None,
            Path::new("/data"),
            &settings("https://m.example.com", 443, Https::Files),
        )
        .unwrap_err();
        assert!(error.to_string().contains("key file"), "{error}");
    }

    #[test]
    fn writing_checks_the_certificate_files_exist() {
        let folder = tempfile::tempdir().unwrap();
        let config = folder.path().join("server.hcl");
        let mut files = settings("https://m.example.com", 443, Https::Files);
        files.certificate_file = Some(folder.path().join("missing.crt"));
        files.key_file = Some(folder.path().join("missing.key"));

        assert!(write(&config, &files, |_| Ok(())).is_err());
        assert!(!config.exists());

        write(
            &config,
            &settings("http://m.example.com:9000", 9000, Https::None),
            |_| Ok(()),
        )
        .unwrap();
        assert!(Config::load(&config).is_ok());
    }

    #[test]
    fn modify_shows_what_the_config_says() {
        let mut automatic = settings("https://m.example.com", 443, Https::Automatic);
        automatic.acme_email = Some("you@example.com".to_string());
        let text = edit(None, Path::new("/data"), &automatic).unwrap();
        let shown = installer_settings(&Config::parse(&text).unwrap());
        assert_eq!(
            shown,
            [
                ("SERVER_ADDRESS", "https://m.example.com".to_string()),
                ("PORT", "443".to_string()),
                ("HTTPS", "automatic".to_string()),
                ("ACME_EMAIL", "you@example.com".to_string()),
                ("CERTIFICATE_FILE", String::new()),
                ("KEY_FILE", String::new()),
            ]
        );

        let mut files = settings("https://m.example.com:8443", 8443, Https::Files);
        files.certificate_file = Some(PathBuf::from("/certs/m.crt"));
        files.key_file = Some(PathBuf::from("/certs/m.key"));
        let text = edit(Some(&text), Path::new("/data"), &files).unwrap();
        let shown = installer_settings(&Config::parse(&text).unwrap());
        assert_eq!(shown[0].1, "https://m.example.com:8443");
        assert_eq!(shown[2].1, "files");
        assert_eq!(shown[4].1, "/certs/m.crt");
    }

    #[test]
    fn the_service_account_is_the_one_windows_makes_for_the_service() {
        let name: Vec<u8> = "MAXNINESSERVER"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let hash = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &name);
        let parts: Vec<String> = hash
            .as_ref()
            .chunks(4)
            .map(|four| u32::from_le_bytes(four.try_into().unwrap()).to_string())
            .collect();
        assert_eq!(SERVICE_ACCOUNT_SID, format!("S-1-5-80-{}", parts.join("-")));

        // The installer has it once, and gives it its data folder and registry key.
        let installer = include_str!("../../../packaging/windows/server.wxs");
        assert!(installer.contains(r#"Account="NT SERVICE\MaxNinesServer""#));
        assert!(installer.contains(&format!(
            r#"<?define ServiceSid = "{SERVICE_ACCOUNT_SID}" ?>"#
        )));
        assert_eq!(installer.matches(SERVICE_ACCOUNT_SID).count(), 1);
        // The folder itself, which it can't delete or rename, then what's inside.
        assert!(installer.contains("(A;;0x1201bf;;;$(var.ServiceSid))"));
        assert!(installer.contains("(A;OICIIO;0x1301bf;;;$(var.ServiceSid))"));
    }

    #[test]
    fn a_setting_given_as_it_was_keeps_a_change_made_by_hand() {
        let given = vec![
            ("SERVER_ADDRESS", "http://m:9000".to_string()),
            ("PORT", "9000".to_string()),
            ("HTTPS", "none".to_string()),
            ("ACME_EMAIL", String::new()),
        ];
        let remembered = BTreeMap::from([
            ("SERVER_ADDRESS".to_string(), "http://old:9000".to_string()),
            ("PORT".to_string(), "9000".to_string()),
            ("HTTPS".to_string(), "none".to_string()),
        ]);
        // By hand: the port, and an email that was never set.
        let current = vec![
            ("SERVER_ADDRESS", "http://old:9000".to_string()),
            ("PORT", "9001".to_string()),
            ("HTTPS", "none".to_string()),
            ("ACME_EMAIL", "hand@example.com".to_string()),
        ];

        let merged = keep_hand_edits(&given, &remembered, &current);
        assert_eq!(
            merged,
            [
                ("SERVER_ADDRESS", "http://m:9000".to_string()),
                ("PORT", "9001".to_string()),
                ("HTTPS", "none".to_string()),
                ("ACME_EMAIL", "hand@example.com".to_string()),
            ]
        );

        // A first install has nothing remembered or in the config yet.
        assert_eq!(keep_hand_edits(&given, &BTreeMap::new(), &[]), given);
    }

    #[test]
    fn the_installer_settings_read_back() {
        let values = vec![
            ("SERVER_ADDRESS", "https://m.example.com".to_string()),
            ("PORT", "443".to_string()),
            ("HTTPS", "files".to_string()),
            ("ACME_EMAIL", String::new()),
            ("CERTIFICATE_FILE", "/c.crt".to_string()),
            ("KEY_FILE", "/c.key".to_string()),
        ];
        let settings = Settings::from_installer(&values).unwrap();
        assert_eq!(settings.port, 443);
        assert_eq!(settings.https, Some(Https::Files));
        assert_eq!(settings.acme_email, None);
        assert_eq!(settings.key_file.as_deref(), Some(Path::new("/c.key")));

        let mut bad = values.clone();
        bad[1].1 = "http".to_string();
        assert!(Settings::from_installer(&bad).is_err());

        // What it remembers is what it reads back.
        let config = Config::parse(&edit(None, Path::new("/data"), &settings).unwrap()).unwrap();
        let names: Vec<&str> = installer_settings(&config)
            .iter()
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(names, INSTALLER_SETTINGS);
    }

    #[test]
    fn the_names_the_installer_remembers_are_the_ones_it_passes() {
        use clap::ValueEnum;
        for https in Https::value_variants() {
            let value = https.to_possible_value().unwrap();
            assert_eq!(value.get_name(), https.as_str());
        }
    }

    #[test]
    fn the_shortcut_opens_the_link() {
        assert_eq!(
            shortcut("http://m:9000/setup/abc"),
            "[InternetShortcut]\r\nURL=http://m:9000/setup/abc\r\n"
        );
    }
}
