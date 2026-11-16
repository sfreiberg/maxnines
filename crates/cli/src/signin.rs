//! Signing in through the browser, as docs/api-app-sign-ins.md describes: OAuth 2.0
//! with PKCE and a loopback redirect, or a code typed on another device for a
//! machine with no browser. Then keeping the tokens fresh, and signing out.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

use crate::failure::Failure;
use crate::http::{Answer, Body, Http};
use crate::server::Server;

/// Which app this is, as the server knows it.
pub const CLIENT_ID: &str = "maxnines-cli";

/// How long someone has to approve it in the browser.
const BROWSER_WAIT: Duration = Duration::from_secs(5 * 60);

/// How long to wait before each new try when a refresh fails for any reason but being
/// signed out. They all fall within the minute the server still takes a refresh token
/// it has just replaced, so an answer lost on the way is asked for again in time.
///
/// Each try waits [`REFRESH_TIMEOUT`] at most, and a try only starts while
/// [`RETRY_WINDOW`] since the first allows, so the last one still reaches the server
/// inside its minute, however slow the earlier ones were.
pub const REFRESH_RETRIES: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(15),
];

/// How long one refresh waits for its answer.
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long after the first try a refresh may start another. The server takes a
/// refresh token it has just replaced for a minute from when it replaced it, which is
/// no earlier than the first try, so this leaves room for a slow network.
pub const RETRY_WINDOW: Duration = Duration::from_secs(45);

/// What signing in or refreshing gives.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Issued {
    pub access_token: String,
    /// Seconds the access token works for.
    pub expires_in: i64,
    pub refresh_token: String,
    pub role: String,
    pub user: String,
}

/// A random verifier, the challenge sent for it, and the state that ties the answer
/// to this request.
#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

fn random(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    // The system's randomness only fails if the system is broken.
    SystemRandom::new()
        .fill(&mut buffer)
        .expect("the system's random number source failed");
    URL_SAFE_NO_PAD.encode(buffer)
}

impl Pkce {
    pub fn new() -> Self {
        let verifier = random(32);
        Self {
            challenge: Self::challenge(&verifier),
            verifier,
            state: random(16),
        }
    }

    /// The SHA-256 of the verifier, in base64url without padding.
    pub fn challenge(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()))
    }
}

/// The page to open in the browser.
pub fn authorize_url(
    server: &Server,
    redirect_uri: &str,
    pkce: &Pkce,
    device: &str,
    role: Option<&str>,
) -> String {
    let mut fields = vec![
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", redirect_uri),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", pkce.state.as_str()),
        ("device", device),
    ];
    if let Some(role) = role {
        fields.push(("role", role));
    }
    let query = serde_urlencoded::to_string(&fields).unwrap_or_default();
    server.url(&format!("/oauth/authorize?{query}"))
}

/// What the browser brought back to the loopback address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Callback {
    Code(String),
    Error(String),
    /// Not the answer: another path, or an answer to some other request.
    NotOurs,
}

/// Reads a request's target, such as `/callback?code=…&state=…`.
pub fn callback(target: &str, state: &str) -> Callback {
    let Some(("/callback", query)) = target.split_once('?') else {
        return Callback::NotOurs;
    };
    let fields: Vec<(String, String)> = serde_urlencoded::from_str(query).unwrap_or_default();
    let field = |name: &str| {
        fields
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.clone()))
    };
    if field("state").as_deref() != Some(state) {
        return Callback::NotOurs;
    }
    match (field("code"), field("error")) {
        (Some(code), _) => Callback::Code(code),
        (None, Some(error)) => Callback::Error(error),
        (None, None) => Callback::NotOurs,
    }
}

/// Signs in through the browser: listens on 127.0.0.1, has `open` open the page where
/// someone approves it, swaps the answer for tokens, and only then tells the browser
/// how it went.
pub fn with_browser(
    http: &Http,
    server: &Server,
    device: &str,
    role: Option<&str>,
    open: &dyn Fn(&str),
) -> anyhow::Result<Issued> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );
    let pkce = Pkce::new();
    open(&authorize_url(server, &redirect_uri, &pkce, device, role));
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + BROWSER_WAIT;
    // Each connection is read on its own, so one a browser opens and never uses
    // holds nothing up; requests come back here to be answered one at a time.
    let (arrived, requests) = std::sync::mpsc::channel::<(TcpStream, String)>();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let arrived = arrived.clone();
                std::thread::spawn(move || {
                    if let Some(target) = read_target(&mut stream) {
                        let _ = arrived.send((stream, target));
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        let (mut stream, target) = match requests.try_recv() {
            Ok(request) => request,
            Err(_) => {
                if Instant::now() >= deadline {
                    return Err(Failure::unreachable(
                        "Nobody allowed it in the browser within 5 minutes. Try again",
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        match callback(&target, &pkce.state) {
            Callback::NotOurs => {
                let status = if target.starts_with("/callback") {
                    "400 Bad Request"
                } else {
                    "404 Not Found"
                };
                reply(&mut stream, status, None);
            }
            Callback::Error(error) => {
                let said = if error == "access_denied" {
                    "Signing in was turned down in the browser".to_string()
                } else {
                    format!("The server wouldn't sign it in: {error}")
                };
                reply(
                    &mut stream,
                    "200 OK",
                    Some("Not signed in to MaxNines. You can close this tab."),
                );
                return Err(Failure::not_allowed(said).into());
            }
            Callback::Code(code) => {
                let issued = redeem(http, server, &code, &redirect_uri, &pkce.verifier);
                let page = match &issued {
                    Ok(_) => "Signed in to MaxNines. You can close this tab.".to_string(),
                    Err(error) => format!(
                        "Not signed in to MaxNines: {}. Try again from the command line.",
                        escape(&error.to_string())
                    ),
                };
                reply(&mut stream, "200 OK", Some(&page));
                return issued.map_err(Into::into);
            }
        }
    }
}

/// Swaps the code the browser brought back for tokens.
fn redeem(
    http: &Http,
    server: &Server,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Issued, Failure> {
    let fields = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ];
    let answer = http.send(
        "POST",
        &server.url("/oauth/token"),
        None,
        Body::Form(&fields),
    )?;
    issued(&answer, "The server wouldn't sign it in")
}

fn issued(answer: &Answer, refused: &str) -> Result<Issued, Failure> {
    if answer.is_success() {
        return serde_json::from_str(&answer.text).map_err(|_| {
            Failure::new(Failure::OTHER, "That didn't answer like a MaxNines server")
        });
    }
    if answer.status >= 500 {
        return Err(Failure::new(
            1,
            format!("The server answered with status {}", answer.status),
        ));
    }
    Err(Failure::refused(match answer.error() {
        Some(error) => format!("{refused}: {error}"),
        None => format!("{refused} (status {})", answer.status),
    }))
}

/// The target of the GET request on `stream`, once its headers have all arrived, as
/// closing with some unread could cut the page off.
fn read_target(stream: &mut TcpStream) -> Option<String> {
    stream.set_nonblocking(false).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 || buffer.len() > 64 * 1024 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buffer);
    let mut parts = text.lines().next()?.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) => Some(target.to_string()),
        _ => None,
    }
}

fn reply(stream: &mut TcpStream, status: &str, words: Option<&str>) {
    let page = words.map_or_else(String::new, |words| {
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>MaxNines</title></head>\
             <body style=\"margin:0;height:100vh;display:grid;place-items:center;background:#0f1114;\
             color:#f3f5f4;font:16px system-ui,sans-serif\"><p>{words}</p></body></html>"
        )
    });
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// What a device is given to show its person.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Signs in with a code someone types on another device: `show` tells them where,
/// and `wait` waits between asks.
pub fn with_device(
    http: &Http,
    server: &Server,
    device: &str,
    role: Option<&str>,
    show: &dyn Fn(&DeviceStart),
    wait: &dyn Fn(Duration),
) -> Result<Issued, Failure> {
    let mut fields = vec![("client_id", CLIENT_ID), ("device", device)];
    if let Some(role) = role {
        fields.push(("role", role));
    }
    let answer = http.send(
        "POST",
        &server.url("/oauth/device"),
        None,
        Body::Form(&fields),
    )?;
    if !answer.is_success() {
        return Err(issued(&answer, "The server wouldn't start signing in").unwrap_err());
    }
    let start: DeviceStart = serde_json::from_str(&answer.text)
        .map_err(|_| Failure::new(Failure::OTHER, "That didn't answer like a MaxNines server"))?;
    show(&start);
    let mut interval = start.interval.max(1);
    loop {
        wait(Duration::from_secs(interval));
        let fields = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", CLIENT_ID),
            ("device_code", start.device_code.as_str()),
        ];
        let answer = http.send(
            "POST",
            &server.url("/oauth/token"),
            None,
            Body::Form(&fields),
        )?;
        if answer.is_success() {
            return issued(&answer, "The server wouldn't sign it in");
        }
        let error = answer
            .json()
            .get("error")
            .and_then(|error| error.as_str().map(str::to_string));
        match error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some("access_denied") => {
                return Err(Failure::not_allowed("Signing in was turned down"));
            }
            Some("expired_token") => {
                return Err(Failure::unreachable(
                    "Nobody entered the code within 10 minutes. Try again",
                ));
            }
            _ => return Err(issued(&answer, "The server wouldn't sign it in").unwrap_err()),
        }
    }
}

/// How swapping a refresh token went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refreshed {
    Issued(Issued),
    /// It's run out or been revoked: signing in again is the only way back.
    SignedOut,
}

/// Swaps a refresh token for new tokens, trying again soon if the answer doesn't come.
pub fn refresh(
    http: &Http,
    server: &Server,
    refresh_token: &str,
    retries: &[Duration],
    wait: &dyn Fn(Duration),
) -> Result<Refreshed, Failure> {
    let fields = [
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", refresh_token),
    ];
    let started = Instant::now();
    let mut retries = retries.iter();
    loop {
        let answer = http.send(
            "POST",
            &server.url("/oauth/token"),
            None,
            Body::Form(&fields),
        );
        let failed = match answer {
            Ok(answer) if answer.is_success() => {
                return issued(&answer, "").map(Refreshed::Issued);
            }
            Ok(answer) if answer.status == 400 && answer.json()["error"] == "invalid_grant" => {
                return Ok(Refreshed::SignedOut);
            }
            Ok(answer) if answer.status < 500 => {
                return Err(issued(&answer, "The server wouldn't refresh the sign in").unwrap_err());
            }
            Ok(answer) => Failure::new(
                Failure::OTHER,
                format!("The server answered with status {}", answer.status),
            ),
            Err(failure) => failure,
        };
        match retries.next() {
            Some(delay) if started.elapsed() + *delay < RETRY_WINDOW => wait(*delay),
            _ => return Err(failed),
        }
    }
}

/// Signs the app out on the server, with either of its tokens.
pub fn revoke(http: &Http, server: &Server, token: &str) -> Result<(), Failure> {
    let fields = [("client_id", CLIENT_ID), ("token", token)];
    let answer = http.send(
        "POST",
        &server.url("/oauth/revoke"),
        None,
        Body::Form(&fields),
    )?;
    if answer.is_success() {
        Ok(())
    } else {
        Err(issued(&answer, "The server wouldn't sign it out").unwrap_err())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_made_as_rfc_7636_says() {
        assert_eq!(
            Pkce::challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let pkce = Pkce::new();
        assert_eq!(pkce.verifier.len(), 43);
        assert_eq!(pkce.challenge, Pkce::challenge(&pkce.verifier));
        assert_ne!(Pkce::new().verifier, pkce.verifier);
    }

    #[test]
    fn the_approval_page_is_asked_for_with_everything_the_server_needs() {
        let server = Server::parse("https://monitor.example.com/alerts").unwrap();
        let pkce = Pkce {
            verifier: "v".to_string(),
            challenge: "c".to_string(),
            state: "s".to_string(),
        };
        let url = authorize_url(
            &server,
            "http://127.0.0.1:5555/callback",
            &pkce,
            "Sam's Mac+Pro",
            Some("responder"),
        );
        assert_eq!(
            url,
            "https://monitor.example.com/oauth/authorize?response_type=code&client_id=maxnines-cli\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A5555%2Fcallback&code_challenge=c\
             &code_challenge_method=S256&state=s&device=Sam%27s+Mac%2BPro&role=responder"
        );
    }

    /// A token endpoint that answers every request with `status` and `body`, giving
    /// back where it is and the forms posted to it.
    fn token_server(
        status: u16,
        body: &'static str,
    ) -> (Server, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = Server::parse(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let (posted, forms) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                // The whole request, headers and form, before answering.
                loop {
                    let text = String::from_utf8_lossy(&buffer).to_string();
                    if let Some((head, form)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if form.len() >= length {
                            let _ = posted.send(form.to_string());
                            break;
                        }
                    }
                    let read = stream.read(&mut chunk).unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (server, forms)
    }

    /// Opens the page as a browser would, choosing Allow, and keeps what the app's
    /// listener showed.
    fn browser(
        code: &'static str,
        shown: std::sync::Arc<std::sync::Mutex<String>>,
    ) -> impl Fn(&str) {
        move |url: &str| {
            let query = url.split_once('?').unwrap().1.to_string();
            let shown = std::sync::Arc::clone(&shown);
            std::thread::spawn(move || {
                let fields: Vec<(String, String)> = serde_urlencoded::from_str(&query).unwrap();
                let field = |name: &str| {
                    fields
                        .iter()
                        .find(|(key, _)| key == name)
                        .unwrap()
                        .1
                        .clone()
                };
                let back = field("redirect_uri");
                let address = back
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap()
                    .to_string();
                let mut stream = TcpStream::connect(address).unwrap();
                let request = format!(
                    "GET /callback?code={code}&state={} HTTP/1.1\r\nHost: x\r\n\r\n",
                    field("state")
                );
                stream.write_all(request.as_bytes()).unwrap();
                let mut page = String::new();
                let _ = stream.read_to_string(&mut page);
                *shown.lock().unwrap() = page;
            });
        }
    }

    #[test]
    fn signing_in_through_the_browser_swaps_the_code_and_only_then_says_so() {
        let (server, forms) = token_server(
            200,
            r#"{"access_token": "mxa_1", "expires_in": 3600, "refresh_token": "mxr_1", "role": "viewer", "user": "you@example.com"}"#,
        );
        let shown = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let issued = with_browser(
            &Http::new(),
            &server,
            "laptop",
            Some("viewer"),
            &browser("mxc_1", std::sync::Arc::clone(&shown)),
        )
        .unwrap();
        assert_eq!(issued.access_token, "mxa_1");
        assert_eq!(issued.role, "viewer");
        let form: Vec<(String, String)> =
            serde_urlencoded::from_str(&forms.recv().unwrap()).unwrap();
        let field = |name: &str| {
            form.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(field("grant_type").as_deref(), Some("authorization_code"));
        assert_eq!(field("code").as_deref(), Some("mxc_1"));
        assert_eq!(Pkce::challenge(&field("code_verifier").unwrap()).len(), 43);
        // The browser's answer waits on the swap, so it's there once this returns.
        for _ in 0..300 {
            if !shown.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            shown.lock().unwrap().contains("Signed in to MaxNines"),
            "{}",
            shown.lock().unwrap()
        );
    }

    #[test]
    fn a_code_the_server_refuses_never_says_signed_in() {
        let (server, _forms) = token_server(
            400,
            r#"{"error": "invalid_grant", "error_description": "That code is <old>"}"#,
        );
        let shown = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let refused = with_browser(
            &Http::new(),
            &server,
            "laptop",
            None,
            &browser("mxc_1", std::sync::Arc::clone(&shown)),
        )
        .unwrap_err();
        assert!(
            refused.to_string().contains("That code is <old>"),
            "{refused}"
        );
        for _ in 0..300 {
            if !shown.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let page = shown.lock().unwrap().clone();
        assert!(!page.contains("Signed in to MaxNines"), "{page}");
        assert!(page.contains("That code is &lt;old&gt;"), "{page}");
    }

    #[test]
    fn a_refresh_is_tried_again_only_while_the_server_would_still_take_it() {
        let (server, forms) = token_server(500, "");
        let waits = std::cell::RefCell::new(Vec::new());
        let wait = |delay: Duration| waits.borrow_mut().push(delay);
        let quick = [Duration::ZERO; 3];
        let failed = refresh(&Http::new(), &server, "mxr_1", &quick, &wait).unwrap_err();
        assert_eq!(failed.code, Failure::OTHER);
        assert_eq!(forms.try_iter().count(), 4);
        assert_eq!(waits.borrow().len(), 3);

        // A wait that would start the next try past the window isn't waited.
        waits.borrow_mut().clear();
        let late = [RETRY_WINDOW];
        refresh(&Http::new(), &server, "mxr_1", &late, &wait).unwrap_err();
        assert_eq!(forms.try_iter().count(), 1);
        assert!(waits.borrow().is_empty());
    }

    #[test]
    fn the_browsers_answer_is_read_and_checked_against_the_state() {
        assert_eq!(
            callback("/callback?code=mxc_1&state=s", "s"),
            Callback::Code("mxc_1".to_string())
        );
        assert_eq!(
            callback("/callback?error=access_denied&state=s", "s"),
            Callback::Error("access_denied".to_string())
        );
        assert_eq!(
            callback("/callback?code=mxc_1&state=other", "s"),
            Callback::NotOurs
        );
        assert_eq!(callback("/callback?code=mxc_1", "s"), Callback::NotOurs);
        assert_eq!(callback("/favicon.ico", "s"), Callback::NotOurs);
    }
}
