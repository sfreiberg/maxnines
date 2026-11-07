//! Being asked to stop. Ctrl+C is the obvious way, but service managers send `SIGTERM`,
//! which would otherwise end a program on the spot, with nothing saved. Windows has no
//! signal for this, and tells a service through `request` instead.

use std::io::Result;

use tokio::sync::Notify;

static REQUESTED: Notify = Notify::const_new();

/// Asks the program to stop, even if it isn't listening yet.
pub fn request() {
    REQUESTED.notify_one();
}

/// Listens from when it's made, so nothing's missed while a program gets on with its
/// work.
pub struct StopSignal {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl StopSignal {
    pub fn listen() -> Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    /// Waits until the program is asked to stop.
    pub async fn wait(&mut self) -> Result<()> {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = self.terminate.recv() => {}
            () = REQUESTED.notified() => {}
        }
        #[cfg(not(unix))]
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            () = REQUESTED.notified() => {}
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    // One test, because a request made in another could be what ends this one's wait.
    #[tokio::test]
    async fn a_plain_kill_or_a_request_asks_a_program_to_stop_instead_of_ending_it() {
        let mut stop = StopSignal::listen().unwrap();

        let sent = Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());

        timeout(Duration::from_secs(5), stop.wait())
            .await
            .expect("the signal was missed")
            .unwrap();

        request();
        timeout(Duration::from_secs(5), stop.wait())
            .await
            .expect("the request was missed")
            .unwrap();
    }
}
