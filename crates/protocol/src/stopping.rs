//! Being asked to stop. Ctrl+C is the obvious way, but service managers send `SIGTERM`,
//! which would otherwise end a program on the spot, with nothing saved.

use std::io::Result;

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
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn a_plain_kill_asks_a_program_to_stop_instead_of_ending_it() {
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
    }
}
