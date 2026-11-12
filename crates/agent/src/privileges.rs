//! Giving up root. An agent started as root splits in two before it does
//! anything else, as programs like sshd do:
//!
//! - The process that goes on to be the agent becomes an ordinary user for good.
//!   It talks to the server, reads what the server sends, collects, and runs the
//!   commands its config defines.
//! - The process that started stays root as a small helper. It has never opened
//!   a network connection, and only hears from the agent, over a socket made
//!   before the split. It does one thing: runs the few built-in actions that see
//!   more as root, which only look.
//!
//! The helper never starts a program, whatever it's asked. Someone who took over
//! the agent could ask it for those built-in actions, and nothing else. A command
//! that needs root goes through `sudo`, under rules root wrote.
//!
//! An agent that isn't started as root runs as it always has, with no helper.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::actions::Ended;

/// What the agent asks its helper for: an action by name, and what the server
/// gave it. Never a command.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Request {
    /// Which question this is, so an answer that comes too late isn't taken for
    /// the answer to the next one.
    id: u64,
    name: String,
    variables: BTreeMap<String, String>,
    timeout_secs: u64,
}

/// How the action a request asked for went.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Answer {
    id: u64,
    ended: Ended,
}

#[cfg(unix)]
pub use unix::{helper, split};

#[cfg(not(unix))]
pub use other::helper;

/// Windows services run with the system's rights already, so nothing is split.
#[cfg(not(unix))]
mod other {
    use std::collections::BTreeMap;

    use super::Ended;

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
}

#[cfg(unix)]
mod unix {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs::DirBuilder;
    use std::io::ErrorKind;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock, PoisonError};
    use std::time::Duration;

    use anyhow::{Context, Result, bail, ensure};
    use maxnines_protocol::actions::{ActionOutcome, MAX_ACTION_TIMEOUT_SECS};
    use nix::sys::signal::{Signal, kill};
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::{ForkResult, Gid, Pid, Uid, User, chown, fork, geteuid, setgid, setuid};
    use serde::Serialize;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::time::timeout;
    use tracing::{error, info, warn};

    use super::{Answer, Ended, Request};
    use crate::actions::{Actions, Executor};
    use crate::config::Config;

    /// Who the agent becomes when its config doesn't say, if there's such a user.
    const DEFAULT_USER: &str = "maxnines";

    /// Where the helper keeps its own files, such as what `disk_space` saw last
    /// time. Only root can write here or in the folder it's in, unlike the
    /// agent's folder, where the agent's user could leave a link for root to
    /// follow.
    #[cfg(target_os = "linux")]
    const HELPER_DIR: &str = "/var/lib/maxnines-agent-helper";
    #[cfg(not(target_os = "linux"))]
    const HELPER_DIR: &str = "/var/db/maxnines-agent-helper";

    /// How long past an action's own limit the agent waits for the helper's answer,
    /// and how long it waits for the helper to take a question.
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
        open: tokio::sync::Mutex<Option<Lines>>,
        /// How many questions have been asked, which numbers the next.
        asked: AtomicU64,
        /// Set once the helper can't be reached, which doesn't change back.
        gone: AtomicBool,
    }

    /// The helper, if this agent was started as root and split, and the helper
    /// is still there.
    pub fn helper() -> Option<&'static Helper> {
        HELPER
            .get()
            .filter(|helper| !helper.gone.load(Ordering::Relaxed))
    }

    impl Helper {
        fn new(socket: StdUnixStream) -> Self {
            Self {
                made: Mutex::new(Some(socket)),
                open: tokio::sync::Mutex::new(None),
                asked: AtomicU64::new(0),
                gone: AtomicBool::new(false),
            }
        }

        /// Asks the helper to run an action and waits for how it went. `None`
        /// means there's no longer a helper to ask.
        pub async fn ask(
            &self,
            name: &str,
            variables: &BTreeMap<String, String>,
            timeout_secs: u64,
        ) -> Option<Ended> {
            let mut open = self.open.lock().await;
            let made = self
                .made
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(made) = made {
                *open = Lines::open(made).ok();
            }
            let Some(lines) = open.as_mut() else {
                self.gone.store(true, Ordering::Relaxed);
                return None;
            };

            let request = Request {
                id: self.asked.fetch_add(1, Ordering::Relaxed) + 1,
                name: name.to_string(),
                variables: variables.clone(),
                timeout_secs,
            };
            // A question the helper only half took would break every one after
            // it, so not taking one in good time is the end of asking.
            let sent = match timeout(ANSWER_GRACE, lines.send(&request)).await {
                Ok(sent) => sent,
                Err(_) => Err(anyhow::anyhow!("it stopped reading")),
            };
            let limit = Duration::from_secs(timeout_secs.min(MAX_ACTION_TIMEOUT_SECS));
            let answer = match sent {
                Ok(()) => timeout(limit + ANSWER_GRACE, lines.answer_to(request.id)).await,
                Err(error) => Ok(Err(error)),
            };
            match answer {
                Ok(Ok(ended)) => Some(ended),
                Ok(Err(error)) => {
                    error!(
                        error = format!("{error:#}"),
                        "the privileged helper is gone, so actions see what the agent's user can"
                    );
                    *open = None;
                    self.gone.store(true, Ordering::Relaxed);
                    None
                }
                // It may only be slow, on a host that's struggling. Its answer
                // to this is passed over when it does come.
                Err(_) => {
                    warn!(action = name, "the privileged helper didn't answer in time");
                    let error = "the privileged helper didn't answer in time";
                    Some(Ended::without_running(ActionOutcome::TimedOut, error))
                }
            }
        }
    }

    /// One end of the socket, read and written a line of JSON at a time.
    struct Lines {
        stream: BufReader<UnixStream>,
        /// The start of a line that hasn't all arrived. It's kept here so that
        /// giving up waiting doesn't lose it and break the line in two.
        partial: Vec<u8>,
    }

    impl Lines {
        fn open(socket: StdUnixStream) -> std::io::Result<Self> {
            socket.set_nonblocking(true)?;
            Ok(Self {
                stream: BufReader::new(UnixStream::from_std(socket)?),
                partial: Vec::new(),
            })
        }

        /// Reads one line, refusing one too long to be real. `None` is the other
        /// end having gone.
        async fn next(&mut self) -> Result<Option<String>> {
            loop {
                let available = self.stream.fill_buf().await?;
                if available.is_empty() {
                    return Ok(None);
                }
                let end = available.iter().position(|byte| *byte == b'\n');
                let take = end.map_or(available.len(), |end| end + 1);
                self.partial.extend_from_slice(&available[..take]);
                self.stream.consume(take);
                ensure!(self.partial.len() <= MAX_LINE, "a line was too long");
                if end.is_some() {
                    let mut line = std::mem::take(&mut self.partial);
                    line.pop();
                    return Ok(Some(String::from_utf8(line)?));
                }
            }
        }

        async fn send(&mut self, message: &impl Serialize) -> Result<()> {
            let mut line = serde_json::to_string(message)?;
            line.push('\n');
            self.stream.get_mut().write_all(line.as_bytes()).await?;
            Ok(())
        }

        /// The helper's answer to one question, passing over answers to earlier
        /// ones that nobody waited for.
        async fn answer_to(&mut self, id: u64) -> Result<Ended> {
            loop {
                let line = self.next().await?.context("it closed the socket")?;
                let answer: Answer =
                    serde_json::from_str(&line).context("it answered with something else")?;
                if answer.id == id {
                    return Ok(answer.ended);
                }
            }
        }
    }

    /// How many threads this process has, where that can be read. Splitting a
    /// process with more than one leaves the new one with whatever the others
    /// were in the middle of, and changing who it is or its environment isn't
    /// safe while another is running.
    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    fn threads() -> Option<usize> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|line| line.starts_with("Threads:"))?;
        line.split_whitespace().nth(1)?.parse().ok()
    }

    #[cfg(target_os = "macos")]
    fn threads() -> Option<usize> {
        let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::zeroed();
        let size = libc::c_int::try_from(size_of::<libc::proc_taskinfo>()).ok()?;
        // SAFETY: `info` is as big as `size` says, and is only read once the
        // system says it filled all of it.
        let filled = unsafe {
            let filled = libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            );
            (filled == size).then(|| info.assume_init())
        };
        usize::try_from(filled?.pti_threadnum).ok()
    }

    #[cfg(target_os = "freebsd")]
    fn threads() -> Option<usize> {
        let mut info = std::mem::MaybeUninit::<libc::kinfo_proc>::zeroed();
        let expected = size_of::<libc::kinfo_proc>();
        let mut size = expected;
        // SAFETY: `info` is as big as `size` says, and is only read once the
        // system says it filled all of it.
        let info = unsafe {
            let name = [
                libc::CTL_KERN,
                libc::KERN_PROC,
                libc::KERN_PROC_PID,
                libc::getpid(),
            ];
            let failed = libc::sysctl(
                name.as_ptr(),
                name.len() as libc::c_uint,
                info.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null(),
                0,
            );
            (failed == 0 && size == expected).then(|| info.assume_init())
        }?;
        // The system says how big it thinks this is, which has to agree for the
        // count to be where it's read from.
        if usize::try_from(info.ki_structsize).ok() != Some(expected) {
            return None;
        }
        usize::try_from(info.ki_numthreads).ok()
    }

    /// Makes the folder the agent keeps its files in, if it isn't there, and gives
    /// that new folder to the agent's user. One that's already there has to be
    /// theirs already. It isn't handed over here: changing who owns what's
    /// inside, as root, would follow whatever links were left there.
    fn make_state_dir(folder: &Path, user: &User) -> Result<()> {
        if let Ok(found) = std::fs::metadata(folder) {
            ensure!(
                found.uid() == user.uid.as_raw(),
                "{folder} doesn't belong to {name}, who the agent runs as, so it couldn't keep \
                 its key there. Give it to them with: chown -R {name}: {folder}",
                folder = folder.display(),
                name = user.name,
            );
            return Ok(());
        }
        std::fs::create_dir_all(folder).with_context(|| format!("making {}", folder.display()))?;
        chown(folder, Some(user.uid), Some(user.gid))
            .with_context(|| format!("giving {} to {}", folder.display(), user.name))?;
        Ok(())
    }

    /// Makes the helper's own folder, if it isn't there, and checks nobody else
    /// can change what's in it.
    fn make_helper_dir(folder: &Path) -> Result<()> {
        match DirBuilder::new().mode(0o700).create(folder) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => bail!("making {}: {error}", folder.display()),
        }
        // Not following a link, as that's one of the things it could be instead.
        let found = std::fs::symlink_metadata(folder)
            .with_context(|| format!("looking at {}", folder.display()))?;
        ensure!(
            found.is_dir() && found.uid() == geteuid().as_raw() && found.mode() & 0o022 == 0,
            "{} isn't a folder that only root can change",
            folder.display()
        );
        Ok(())
    }

    /// Where the helper keeps its files, or `None`, with a warning, to keep
    /// nothing between restarts.
    fn helper_dir(folder: &Path) -> Option<PathBuf> {
        match make_helper_dir(folder) {
            Ok(()) => Some(folder.to_path_buf()),
            Err(error) => {
                warn!(
                    error = format!("{error:#}"),
                    "the privileged helper has nowhere to keep files, so disk_space won't know \
                     what changed since before the agent restarted"
                );
                None
            }
        }
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
        ensure!(
            threads().is_none_or(|threads| threads == 1),
            "the agent had already started threads, so it can't give up root safely"
        );

        if !config.privileged_helper {
            become_user(&user)?;
            info!(user = user.name, "gave up root, with no helper kept");
            return Ok(());
        }

        let (agents, helpers) = StdUnixStream::pair().context("making the helper's socket")?;
        // No commands: the helper only has the built-in actions to run.
        let kept = helper_dir(Path::new(HELPER_DIR));
        let executor = Executor::new(Actions::new(), config.built_in_actions, kept.as_deref());

        // SAFETY: this process has one thread, checked above where the system can
        // say, so the new process is a whole copy with nothing half done.
        match unsafe { fork() }.context("splitting off the agent")? {
            ForkResult::Child => {
                drop(helpers);
                become_user(&user)?;
                // Only ever set here, once.
                let _ = HELPER.set(Helper::new(agents));
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
        let mut lines = match Lines::open(socket) {
            Ok(lines) => lines,
            Err(error) => {
                error!(%error, "the privileged helper couldn't open its socket");
                return;
            }
        };
        loop {
            let line = match lines.next().await {
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
            let answer = match serde_json::from_str::<Request>(&line) {
                Ok(request) => {
                    let ended = executor
                        .run_privileged(&request.name, &request.variables, request.timeout_secs)
                        .await;
                    info!(
                        action = request.name,
                        outcome = ended.outcome.as_str(),
                        "the privileged helper ran an action"
                    );
                    Answer {
                        id: request.id,
                        ended,
                    }
                }
                // The agent numbers its questions from one, so this answers none.
                Err(_) => Answer {
                    id: 0,
                    ended: Ended::without_running(ActionOutcome::Refused, "it wasn't a request"),
                },
            };
            if lines.send(&answer).await.is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::actions::Action;

        /// A helper serving one end of a socket, and the agent's end of it.
        fn helper_with(actions: Actions, state_dir: Option<&Path>) -> Helper {
            let (agents, helpers) = StdUnixStream::pair().unwrap();
            tokio::spawn(serve(helpers, Executor::new(actions, true, state_dir)));
            Helper::new(agents)
        }

        /// Both ends of a socket, with nothing serving either.
        fn pair() -> (Lines, Lines) {
            let (agents, helpers) = StdUnixStream::pair().unwrap();
            (Lines::open(agents).unwrap(), Lines::open(helpers).unwrap())
        }

        fn answer(id: u64, error: &str) -> Answer {
            Answer {
                id,
                ended: Ended::without_running(ActionOutcome::Failed, error),
            }
        }

        #[tokio::test]
        async fn the_helper_only_runs_the_built_ins_that_see_more_as_root() {
            // The real one is given no commands at all. Even one that was
            // wouldn't run them.
            let plain = Action {
                command: vec!["/bin/echo".to_string(), "plain".to_string()],
            };
            let helper = helper_with(Actions::from([("plain".to_string(), plain)]), None);
            let none = BTreeMap::new();

            let plain = helper.ask("plain", &none, 5).await.unwrap();
            assert_eq!(plain.outcome, ActionOutcome::Refused);
            assert_eq!(plain.output, "");
            // So is a built-in that sees everything as anyone.
            let top = helper.ask("top_cpu", &none, 5).await.unwrap();
            assert_eq!(top.outcome, ActionOutcome::Refused);
            let unknown = helper.ask("reboot", &none, 5).await.unwrap();
            assert_eq!(unknown.outcome, ActionOutcome::NotDefined);

            // What it does run is checked as ever.
            let missing = helper.ask("disk_space", &none, 5).await.unwrap();
            assert_eq!(missing.outcome, ActionOutcome::Refused);
            let too_long = helper.ask("disk_io", &none, MAX_ACTION_TIMEOUT_SECS + 1);
            assert_eq!(too_long.await.unwrap().outcome, ActionOutcome::Refused);
        }

        #[tokio::test]
        async fn the_helper_keeps_what_disk_space_saw_in_its_own_folder() {
            let kept = tempfile::tempdir().unwrap();
            let helper = helper_with(Actions::new(), Some(kept.path()));
            let folder = tempfile::tempdir().unwrap();
            std::fs::write(folder.path().join("file"), vec![1u8; 8192]).unwrap();
            let given = BTreeMap::from([("disk".to_string(), folder.path().display().to_string())]);
            let ran = helper.ask("disk_space", &given, 30).await.unwrap();
            assert_eq!(ran.outcome, ActionOutcome::Succeeded, "{ran:?}");
            assert!(ran.output.contains("found"), "{ran:?}");
            assert!(kept.path().join("disk_space.json").exists());
        }

        #[tokio::test]
        async fn anything_that_is_not_a_request_is_refused_and_the_helper_carries_on() {
            let (agents, helpers) = StdUnixStream::pair().unwrap();
            tokio::spawn(serve(helpers, Executor::new(Actions::new(), true, None)));
            let mut lines = Lines::open(agents).unwrap();

            for junk in ["run rm -rf /\n", "{\"command\": [\"/bin/sh\"]}\n", "\n"] {
                let stream = lines.stream.get_mut();
                stream.write_all(junk.as_bytes()).await.unwrap();
                let line = lines.next().await.unwrap().unwrap();
                let answer: Answer = serde_json::from_str(&line).unwrap();
                assert_eq!(answer.ended.outcome, ActionOutcome::Refused, "{junk:?}");
            }
        }

        #[tokio::test]
        async fn a_helper_that_has_gone_is_not_asked_again() {
            let (agents, helpers) = StdUnixStream::pair().unwrap();
            drop(helpers);
            let helper = Helper::new(agents);
            let none = BTreeMap::new();
            assert_eq!(helper.ask("disk_io", &none, 5).await, None);
            assert!(helper.gone.load(Ordering::Relaxed));
            assert_eq!(helper.ask("disk_io", &none, 5).await, None);
        }

        #[tokio::test]
        async fn an_answer_that_came_too_late_is_not_taken_for_the_next() {
            let (mut agents, mut helpers) = pair();
            helpers.send(&answer(1, "late")).await.unwrap();
            helpers.send(&answer(2, "wanted")).await.unwrap();
            let ended = agents.answer_to(2).await.unwrap();
            assert_eq!(ended.error.as_deref(), Some("wanted"));
        }

        #[tokio::test]
        async fn giving_up_waiting_does_not_break_a_line_in_two() {
            let (mut agents, mut helpers) = pair();
            let line = serde_json::to_string(&answer(1, "whole")).unwrap();
            let (start, rest) = line.split_at(10);
            let stream = helpers.stream.get_mut();
            stream.write_all(start.as_bytes()).await.unwrap();
            // The rest hasn't been sent, so however long this waits it gives up.
            let waited = timeout(Duration::from_millis(50), agents.answer_to(1)).await;
            assert!(waited.is_err());

            let stream = helpers.stream.get_mut();
            stream.write_all(rest.as_bytes()).await.unwrap();
            stream.write_all(b"\n").await.unwrap();
            let ended = agents.answer_to(1).await.unwrap();
            assert_eq!(ended.error.as_deref(), Some("whole"));
        }

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        #[test]
        fn threads_are_counted() {
            // Other tests come and go, so only that it's more than the one a
            // test never runs on alone: this thread and the one that started it.
            assert!(threads().unwrap() >= 2);
        }

        #[test]
        fn the_agents_folder_has_to_be_its_users() {
            let folder = tempfile::tempdir().unwrap();
            let me = User::from_uid(geteuid()).unwrap().unwrap();
            let before = std::fs::metadata(folder.path()).unwrap();
            make_state_dir(folder.path(), &me).unwrap();
            let after = std::fs::metadata(folder.path()).unwrap();
            assert_eq!((before.uid(), before.mode()), (after.uid(), after.mode()));

            let new = folder.path().join("a/b");
            make_state_dir(&new, &me).unwrap();
            assert_eq!(std::fs::metadata(&new).unwrap().uid(), me.uid.as_raw());

            // Someone else's is refused, saying how to hand it over.
            let other = User {
                uid: Uid::from_raw(me.uid.as_raw() + 1),
                name: "someone".to_string(),
                ..me
            };
            let error = make_state_dir(folder.path(), &other).unwrap_err();
            let expected = format!("chown -R someone: {}", folder.path().display());
            assert!(error.to_string().contains(&expected), "{error}");
        }

        #[test]
        fn the_helpers_folder_is_only_its_own() {
            let within = tempfile::tempdir().unwrap();
            let folder = within.path().join("helper");
            assert_eq!(helper_dir(&folder), Some(folder.clone()));
            assert_eq!(std::fs::metadata(&folder).unwrap().mode() & 0o777, 0o700);
            // And again, now that it's there.
            assert_eq!(helper_dir(&folder), Some(folder.clone()));

            // A link to somewhere else, a file, a folder others can write to, and
            // one that can't be made are all turned down.
            let link = within.path().join("link");
            std::os::unix::fs::symlink(&folder, &link).unwrap();
            assert_eq!(helper_dir(&link), None);
            let file = within.path().join("file");
            std::fs::write(&file, "").unwrap();
            assert_eq!(helper_dir(&file), None);
            let open = within.path().join("open");
            DirBuilder::new().mode(0o777).create(&open).unwrap();
            let all = std::os::unix::fs::PermissionsExt::from_mode(0o777);
            std::fs::set_permissions(&open, all).unwrap();
            assert_eq!(helper_dir(&open), None);
            assert_eq!(helper_dir(&within.path().join("no/such/place")), None);
        }
    }
}
