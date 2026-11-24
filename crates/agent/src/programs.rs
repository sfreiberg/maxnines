//! Running another program for what it prints, as the collectors that ask the
//! system's own tools do: smartctl for drives, and each package manager for its
//! updates.

use std::time::Duration;

/// What a program did: its exit code, what it printed, and what it said went wrong.
pub struct Ran {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Runs a program with nothing to read and the C locale, so what it prints is in
/// the words this reads, giving up after `limit`. A program still running then is
/// stopped.
pub async fn run(program: &str, arguments: &[&str], limit: Duration) -> Result<Ran, String> {
    let command = tokio::process::Command::new(program)
        .args(arguments)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(limit, command).await {
        Err(_) => Err(format!(
            "{program} took longer than {} seconds",
            limit.as_secs()
        )),
        Ok(Err(error)) => Err(format!("couldn't run {program}: {error}")),
        Ok(Ok(output)) => Ok(Ran {
            code: output.status.code(),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }),
    }
}

/// The first of these places that exists.
#[cfg(unix)]
pub fn first_of(places: &[&'static str]) -> Option<&'static str> {
    places
        .iter()
        .copied()
        .find(|place| std::path::Path::new(place).exists())
}

/// sudo saying it won't, on its own: `sudo -n` exits 1 with nothing printed and its
/// reason, starting `sudo:`, on stderr.
#[cfg(unix)]
pub fn refused_by_sudo(ran: &Ran) -> bool {
    ran.stdout.is_empty() && ran.code == Some(1) && ran.stderr.starts_with("sudo:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn a_program_runs_in_the_c_locale() {
        let ran = run("/bin/sh", &["-c", "echo $LC_ALL"], Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&ran.stdout).trim(), "C");
        assert_eq!(ran.code, Some(0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_program_that_takes_too_long_is_given_up_on() {
        let error = run("/bin/sleep", &["5"], Duration::from_millis(50))
            .await
            .err()
            .unwrap();
        assert!(error.contains("took longer than"), "{error}");
    }

    #[tokio::test]
    async fn a_missing_program_says_so() {
        let error = run("/nonexistent/program", &[], Duration::from_secs(5))
            .await
            .err()
            .unwrap();
        assert!(
            error.starts_with("couldn't run /nonexistent/program"),
            "{error}"
        );
    }
}
