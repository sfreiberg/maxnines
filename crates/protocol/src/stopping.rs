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

/// Listens from when it's made, for Ctrl+C as well as the rest, so nothing's missed
/// while a program gets on with its work.
pub struct StopSignal {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    interrupt: tokio::signal::windows::CtrlC,
}

impl StopSignal {
    pub fn listen() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                interrupt: tokio::signal::windows::ctrl_c()?,
            })
        }
    }

    /// Waits until the program is asked to stop.
    pub async fn wait(&mut self) -> Result<()> {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
            () = REQUESTED.notified() => {}
        }
        #[cfg(windows)]
        tokio::select! {
            _ = self.interrupt.recv() => {}
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

        // Ctrl+C sent before anything waits is still heard, rather than ending the
        // program on the spot.
        for signal in ["-TERM", "-INT"] {
            let sent = Command::new("kill")
                .args([signal, &std::process::id().to_string()])
                .status()
                .unwrap();
            assert!(sent.success());

            timeout(Duration::from_secs(5), stop.wait())
                .await
                .expect("the signal was missed")
                .unwrap();
        }

        request();
        timeout(Duration::from_secs(5), stop.wait())
            .await
            .expect("the request was missed")
            .unwrap();
    }
}
