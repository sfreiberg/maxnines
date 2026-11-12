//! Giving up root. An agent started as root splits in two before it does
//! anything else, as programs like sshd do:
//!
//! - The process that goes on to be the agent becomes an ordinary user for good.
//!   It talks to the server, reads what the server sends, and collects.
//! - The process that started stays root as a small helper. It has never opened
//!   a network connection, and only hears from the agent, over a socket made
//!   before the split. It does two things: runs the few built-in actions that
//!   see more as root, and runs the actions whose config says who they run as.
//!
//! The helper reads the config for itself while it's still the only process, so
//! it never takes the agent's word for what an action is: the agent sends a name,
//! and the helper runs what root's own file says that name means, or refuses.
//! Someone who took over the agent could ask for those, and nothing else.
//!
//! An agent that isn't started as root runs as it always has, with no helper.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::actions::{Ended, RunAs};

/// What the agent asks its helper for: an action by name, and what the server
/// gave it. Never a command.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Request {
    name: String,
    variables: BTreeMap<String, String>,
    timeout_secs: u64,
}

#[cfg(unix)]
pub use unix::{helper, is_current_user, look_up, split};

#[cfg(not(unix))]
pub use other::{helper, is_current_user, look_up};

/// Windows services run with the system's rights already, so nothing is split.
#[cfg(not(unix))]
mod other {
    use std::collections::BTreeMap;

    use anyhow::{Result, bail};

    use super::{Ended, RunAs};

    pub struct Helper;

    impl Helper {
        pub async fn ask(
            &self,
            _name: &str,
            _variables: &BTreeMap<String, String>,
            _timeout_secs: u64,
        ) -> Option<Ended> {
            None
        }
    }

    pub fn helper() -> Option<&'static Helper> {
        None
    }

    pub fn is_current_user(_name: &str) -> bool {
        false
    }

    pub fn look_up(name: &str) -> Result<RunAs> {
        bail!("running as {name} isn't supported on this system")
    }
}

#[cfg(unix)]
mod unix {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock, PoisonError};
    use std::time::Duration;

    use anyhow::{Context, Result, bail, ensure};
    use maxnines_protocol::actions::{ActionOutcome, MAX_ACTION_TIMEOUT_SECS};
    use nix::sys::signal::{Signal, kill};
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::{ForkResult, Gid, Pid, Uid, User, chown, fork, geteuid, setgid, setuid};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::time::timeout;
    use tracing::{error, info, warn};

    use super::{Ended, Request, RunAs};
    use crate::actions::Executor;
    use crate::config::Config;

    /// Who the agent becomes when its config doesn't say, if there's such a user.
    const DEFAULT_USER: &str = "maxnines";

    /// How long past an action's own limit the agent waits for the helper's answer.
    const ANSWER_GRACE: Duration = Duration::from_secs(15);

    /// How often the helper looks whether the agent has ended, besides being told.
    const AGENT_CHECK_EVERY: Duration = Duration::from_secs(5);

    /// The longest line either side reads, which an action's output and its JSON
    /// escaping fit in many times over.
    const MAX_LINE: usize = 4 * 1024 * 1024;

    static HELPER: OnceLock<Helper> = OnceLock::new();

    /// The agent's end of the socket to its helper.
    pub struct Helper {
        /// As it was made before the split. It becomes `open` on first use, as
        /// that needs the agent's runtime, which starts after the split.
        made: Mutex<Option<StdUnixStream>>,
        open: tokio::sync::Mutex<Option<BufReader<UnixStream>>>,
    }

    /// The helper, if this agent was started as root and split.
    pub fn helper() -> Option<&'static Helper> {
        HELPER.get()
    }

    impl Helper {
        /// Asks the helper to run an action and waits for how it went. `None`
        /// means there's no longer a helper to ask.
        pub async fn ask(
            &self,
            name: &str,
            variables: &BTreeMap<String, String>,
            timeout_secs: u64,
        ) -> Option<Ended> {
            let mut open = self.open.lock().await;
            if open.is_none() {
                let made = self
                    .made
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()?;
                made.set_nonblocking(true).ok()?;
                *open = Some(BufReader::new(UnixStream::from_std(made).ok()?));
            }
            let stream = open.as_mut()?;

            let request = Request {
                name: name.to_string(),
                variables: variables.clone(),
                timeout_secs,
            };
            let limit = Duration::from_secs(timeout_secs.min(MAX_ACTION_TIMEOUT_SECS));
            let answer = timeout(limit + ANSWER_GRACE, exchange(stream, &request)).await;
            match answer {
                Ok(Ok(ended)) => Some(ended),
                // Whatever came next would answer the wrong question, so that's
                // the end of asking.
                Ok(Err(error)) => {
                    error!(
                        error = format!("{error:#}"),
                        "the privileged helper is gone"
                    );
                    *open = None;
                    None
                }
                Err(_) => {
                    error!("the privileged helper stopped answering");
                    *open = None;
                    None
                }
            }
        }
    }

    /// One question and its answer, each a line of JSON.
    async fn exchange(stream: &mut BufReader<UnixStream>, request: &Request) -> Result<Ended> {
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        stream.get_mut().write_all(line.as_bytes()).await?;
        let answer = read_line(stream).await?.context("it closed the socket")?;
        serde_json::from_str(&answer).context("it answered with something else")
    }

    /// Reads one line, refusing one too long to be real. `None` is the other end
    /// having gone.
    async fn read_line(stream: &mut BufReader<UnixStream>) -> Result<Option<String>> {
        let mut line = Vec::new();
        loop {
            let available = stream.fill_buf().await?;
            if available.is_empty() {
                return Ok(None);
            }
            let end = available.iter().position(|byte| *byte == b'\n');
            let take = end.map_or(available.len(), |end| end + 1);
            line.extend_from_slice(&available[..take]);
            stream.consume(take);
            ensure!(line.len() <= MAX_LINE, "a line was too long");
            if end.is_some() {
                line.pop();
                return Ok(Some(String::from_utf8(line)?));
            }
        }
    }

    /// Whether `name` is who this process is running as, so nothing has to change
    /// to run as them.
    pub fn is_current_user(name: &str) -> bool {
        User::from_uid(geteuid())
            .ok()
            .flatten()
            .is_some_and(|user| user.name == name)
    }

    /// Who a user is, for running a command as them.
    pub fn look_up(name: &str) -> Result<RunAs> {
        let user = User::from_name(name)
            .with_context(|| format!("looking up the user {name}"))?
            .with_context(|| format!("there's no user called {name}"))?;
        Ok(RunAs {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
        })
    }

    /// How many threads this process has, where that can be read. Splitting a
    /// process with more than one leaves the new one with whatever the others
    /// were in the middle of.
    fn threads() -> Option<usize> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|line| line.starts_with("Threads:"))?;
        line.split_whitespace().nth(1)?.parse().ok()
    }

    /// Makes the folder the agent keeps its files in, if it isn't there, and gives
    /// that new folder to the agent's user. One that's already there is left
    /// exactly as it is: changing who owns what's inside, as root, would follow
    /// whatever links an earlier agent had been tricked into leaving there.
    fn make_state_dir(folder: &Path, user: &User) -> Result<()> {
        if folder.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(folder).with_context(|| format!("making {}", folder.display()))?;
        chown(folder, Some(user.uid), Some(user.gid))
            .with_context(|| format!("giving {} to {}", folder.display(), user.name))?;
        Ok(())
    }

    /// Becomes `user` for good: their groups, then their group, then them, in the
    /// order that works, as each step needs rights the next one gives up.
    fn become_user(user: &User) -> Result<()> {
        let name = CString::new(user.name.as_str()).context("the user's name")?;
        // SAFETY: `name` is a valid C string that outlives the call, and nothing
        // else is running in this process to see the group list change.
        #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
        let set = unsafe { libc::initgroups(name.as_ptr(), user.gid.as_raw() as _) };
        ensure!(
            set == 0,
            "setting {}'s groups failed: {}",
            user.name,
            std::io::Error::last_os_error()
        );
        setgid(user.gid).context("setting the group")?;
        setuid(user.uid).context("setting the user")?;

        // Checked rather than trusted: if any of root were left, this would work.
        ensure!(
            setuid(Uid::from_raw(0)).is_err() && setgid(Gid::from_raw(0)).is_err(),
            "root's rights could be taken back, so they weren't really given up"
        );
        // Nothing this starts can gain rights either, such as through sudo.
        #[cfg(target_os = "linux")]
        nix::sys::prctl::set_no_new_privs().context("giving up gaining rights")?;

        // What commands expect to find, which still said root.
        // SAFETY: this process has one thread, so nothing reads the environment
        // while it changes.
        unsafe {
            std::env::set_var("HOME", &user.dir);
            std::env::set_var("USER", &user.name);
            std::env::set_var("LOGNAME", &user.name);
        }
        Ok(())
    }

    /// Who an agent started as root becomes, or `None` to stay root: because the
    /// config says root, or names nobody and there's no `maxnines` user, as on a
    /// system where it was never packaged.
    fn user_to_become(config: &Config) -> Result<Option<User>> {
        let (name, chosen) = match &config.run_as {
            Some(name) => (name.as_str(), true),
            None => (DEFAULT_USER, false),
        };
        let user = User::from_name(name).with_context(|| format!("looking up the user {name}"))?;
        match user {
            Some(user) if user.uid.is_root() => Ok(None),
            Some(user) => Ok(Some(user)),
            None if chosen => bail!("run_as names {name}, and there's no such user"),
            None => {
                warn!(
                    "started as root, and there's no {DEFAULT_USER} user to run as, so staying \
                     root. Set run_as in the agent's config to run as someone else"
                );
                Ok(None)
            }
        }
    }

    /// Splits an agent that was started as root, as the top of this file describes.
    /// It returns in the process that carries on as the agent. The helper never
    /// returns: it ends when the agent does, with the agent's exit status.
    ///
    /// Call this before anything starts a thread, which means before the runtime.
    pub fn split(config: &Config) -> Result<()> {
        if !geteuid().is_root() {
            if config.run_as.is_some() {
                warn!("run_as only applies to an agent started as root, so it's ignored");
            }
            return Ok(());
        }
        let Some(user) = user_to_become(config)? else {
            return Ok(());
        };
        make_state_dir(&config.state_dir, &user)?;

        if !config.privileged_helper {
            become_user(&user)?;
            info!(user = user.name, "gave up root, with no helper kept");
            return Ok(());
        }

        ensure!(
            threads().is_none_or(|threads| threads == 1),
            "the agent had already started threads, so it can't split safely"
        );
        let (agents, helpers) = StdUnixStream::pair().context("making the helper's socket")?;
        // The helper's copy of what can be run, taken from root's file now, so
        // nothing the agent later says or changes can alter it.
        let executor = Executor::new(config.actions.clone(), config.built_in_actions, None);

        // SAFETY: this process has one thread, checked above where the system can
        // say, so the new process is a whole copy with nothing half done.
        match unsafe { fork() }.context("splitting off the agent")? {
            ForkResult::Child => {
                drop(helpers);
                become_user(&user)?;
                let helper = Helper {
                    made: Mutex::new(Some(agents)),
                    open: tokio::sync::Mutex::new(None),
                };
                // Only ever set here, once.
                let _ = HELPER.set(helper);
                info!(
                    user = user.name,
                    "gave up root, keeping a privileged helper"
                );
                Ok(())
            }
            ForkResult::Parent { child } => {
                drop(agents);
                let code = help(helpers, child, executor);
                std::process::exit(code);
            }
        }
    }

    /// The helper's whole life: answer the agent until it goes, pass on being
    /// asked to stop, and end as the agent ended.
    fn help(socket: StdUnixStream, agent: Pid, executor: Executor) -> i32 {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        match runtime {
            Ok(runtime) => {
                let ended = runtime.block_on(async {
                    let mut serving = Some(tokio::spawn(serve(socket, executor)));
                    let mut terminate = signal(SignalKind::terminate())?;
                    let mut interrupt = signal(SignalKind::interrupt())?;
                    let mut child_ended = signal(SignalKind::child())?;
                    // In case the agent ended before anything was listening.
                    let mut check = tokio::time::interval(AGENT_CHECK_EVERY);
                    loop {
                        if let Some(code) = exit_code(agent, false) {
                            return std::io::Result::Ok(code);
                        }
                        tokio::select! {
                            // The agent carries on without a helper if this fails.
                            _ = async { serving.as_mut()?.await.ok() }, if serving.is_some() => {
                                serving = None;
                            }
                            // Whoever asks the process that was started to stop
                            // means the agent, which saves its work before it goes.
                            _ = terminate.recv() => { let _ = kill(agent, Signal::SIGTERM); }
                            _ = interrupt.recv() => { let _ = kill(agent, Signal::SIGINT); }
                            _ = child_ended.recv() => {}
                            _ = check.tick() => {}
                        }
                    }
                });
                match ended {
                    Ok(code) => return code,
                    Err(error) => error!(%error, "the privileged helper can't listen for signals"),
                }
            }
            Err(error) => error!(%error, "the privileged helper couldn't start"),
        }
        // Without a helper the agent still runs, and this still ends when it does.
        exit_code(agent, true).unwrap_or(1)
    }

    /// What the agent exited with, if it has, or once it has when `wait` is set.
    fn exit_code(agent: Pid, wait: bool) -> Option<i32> {
        let flags = (!wait).then_some(WaitPidFlag::WNOHANG);
        match waitpid(agent, flags) {
            Ok(WaitStatus::Exited(_, code)) => Some(code),
            Ok(WaitStatus::Signaled(_, signal, _)) => Some(128 + signal as i32),
            Ok(_) => None,
            // It isn't there to wait for.
            Err(_) => Some(1),
        }
    }

    /// Answers the agent's requests, one at a time, until it closes the socket.
    async fn serve(socket: StdUnixStream, executor: Executor) {
        let opened = socket
            .set_nonblocking(true)
            .and_then(|()| UnixStream::from_std(socket));
        let mut stream = match opened {
            Ok(stream) => BufReader::new(stream),
            Err(error) => {
                error!(%error, "the privileged helper couldn't open its socket");
                return;
            }
        };
        loop {
            let line = match read_line(&mut stream).await {
                Ok(Some(line)) => line,
                Ok(None) => return,
                Err(error) => {
                    error!(
                        error = format!("{error:#}"),
                        "the privileged helper stopped reading"
                    );
                    return;
                }
            };
            let ended = match serde_json::from_str::<Request>(&line) {
                Ok(request) => {
                    let ended = executor
                        .run_privileged(&request.name, &request.variables, request.timeout_secs)
                        .await;
                    info!(
                        action = request.name,
                        outcome = ended.outcome.as_str(),
                        "the privileged helper ran an action"
                    );
                    ended
                }
                Err(_) => Ended::without_running(ActionOutcome::Refused, "it wasn't a request"),
            };
            let Ok(mut answer) = serde_json::to_string(&ended) else {
                return;
            };
            answer.push('\n');
            if stream.get_mut().write_all(answer.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::MetadataExt;

        use super::*;
        use crate::actions::{Action, Actions};

        fn action(command: &[&str], user: Option<&str>) -> Action {
            Action {
                command: command.iter().map(|part| (*part).to_string()).collect(),
                user: user.map(str::to_string),
            }
        }

        /// A helper serving one end of a socket, and the agent's end of it.
        fn helper_with(actions: Actions) -> Helper {
            let (agents, helpers) = StdUnixStream::pair().unwrap();
            tokio::spawn(serve(helpers, Executor::new(actions, true, None)));
            Helper {
                made: Mutex::new(Some(agents)),
                open: tokio::sync::Mutex::new(None),
            }
        }

        fn current_user() -> String {
            User::from_uid(geteuid()).unwrap().unwrap().name
        }

        #[tokio::test]
        async fn the_helper_only_runs_what_needs_it() {
            let me = current_user();
            let actions = Actions::from([
                ("plain".to_string(), action(&["/bin/echo", "plain"], None)),
                (
                    "as_me".to_string(),
                    action(&["/bin/echo", "as", "{hostname}"], Some(&me)),
                ),
            ]);
            let helper = helper_with(actions);
            let none = BTreeMap::new();

            // A command with no user is the agent's own to run, however it asks.
            let plain = helper.ask("plain", &none, 5).await.unwrap();
            assert_eq!(plain.outcome, ActionOutcome::Refused);
            assert_eq!(plain.output, "");
            // So is a built-in that sees everything as anyone.
            let top = helper.ask("top_cpu", &none, 5).await.unwrap();
            assert_eq!(top.outcome, ActionOutcome::Refused);
            let unknown = helper.ask("reboot", &none, 5).await.unwrap();
            assert_eq!(unknown.outcome, ActionOutcome::NotDefined);

            // One that names a user runs, with what it was given checked as ever.
            let missing = helper.ask("as_me", &none, 5).await.unwrap();
            assert_eq!(missing.outcome, ActionOutcome::Refused);
            let given = BTreeMap::from([("hostname".to_string(), "web-1".to_string())]);
            let ran = helper.ask("as_me", &given, 5).await.unwrap();
            assert_eq!(ran.outcome, ActionOutcome::Succeeded, "{ran:?}");
            assert_eq!(ran.output, "as web-1\n");
            let too_long = helper
                .ask("as_me", &given, MAX_ACTION_TIMEOUT_SECS + 1)
                .await;
            assert_eq!(too_long.unwrap().outcome, ActionOutcome::Refused);
        }

        #[tokio::test]
        async fn the_helper_runs_the_built_ins_that_see_more_as_root() {
            let helper = helper_with(Actions::new());
            let folder = tempfile::tempdir().unwrap();
            std::fs::write(folder.path().join("file"), vec![1u8; 8192]).unwrap();
            let given = BTreeMap::from([("disk".to_string(), folder.path().display().to_string())]);
            let ran = helper.ask("disk_space", &given, 30).await.unwrap();
            assert_eq!(ran.outcome, ActionOutcome::Succeeded, "{ran:?}");
            assert!(ran.output.contains("found"), "{ran:?}");
        }

        #[tokio::test]
        async fn anything_that_is_not_a_request_is_refused_and_the_helper_carries_on() {
            let (agents, helpers) = StdUnixStream::pair().unwrap();
            tokio::spawn(serve(helpers, Executor::new(Actions::new(), true, None)));
            agents.set_nonblocking(true).unwrap();
            let mut stream = BufReader::new(UnixStream::from_std(agents).unwrap());

            for junk in ["run rm -rf /\n", "{\"command\": [\"/bin/sh\"]}\n", "\n"] {
                stream.get_mut().write_all(junk.as_bytes()).await.unwrap();
                let answer = read_line(&mut stream).await.unwrap().unwrap();
                let ended: Ended = serde_json::from_str(&answer).unwrap();
                assert_eq!(ended.outcome, ActionOutcome::Refused, "{junk:?}");
            }
        }

        #[tokio::test]
        async fn a_helper_that_has_gone_is_not_asked_again() {
            let (agents, helpers) = StdUnixStream::pair().unwrap();
            drop(helpers);
            let helper = Helper {
                made: Mutex::new(Some(agents)),
                open: tokio::sync::Mutex::new(None),
            };
            let none = BTreeMap::new();
            assert_eq!(helper.ask("disk_io", &none, 5).await, None);
            assert_eq!(helper.ask("disk_io", &none, 5).await, None);
        }

        #[test]
        fn users_are_looked_up_by_name() {
            let me = current_user();
            assert!(is_current_user(&me));
            assert!(!is_current_user("no-such-user-maxnines"));
            assert_eq!(look_up(&me).unwrap().uid, geteuid().as_raw());
            assert!(look_up("no-such-user-maxnines").is_err());
        }

        #[test]
        fn a_folder_that_is_already_there_is_left_alone() {
            let folder = tempfile::tempdir().unwrap();
            let me = User::from_uid(geteuid()).unwrap().unwrap();
            let before = std::fs::metadata(folder.path()).unwrap();
            make_state_dir(folder.path(), &me).unwrap();
            let after = std::fs::metadata(folder.path()).unwrap();
            assert_eq!((before.uid(), before.mode()), (after.uid(), after.mode()));

            let new = folder.path().join("a/b");
            make_state_dir(&new, &me).unwrap();
            assert_eq!(std::fs::metadata(&new).unwrap().uid(), me.uid.as_raw());
        }
    }
}
