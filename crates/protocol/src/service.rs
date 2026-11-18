//! Running as a Windows service. Windows doesn't simply start a program and signal it
//! to stop: a service has to connect to the service manager and report how it's doing,
//! or Windows gives up on it. It also starts with no terminal, in the system folder.

use std::ffi::{OsStr, OsString};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use clap::Subcommand;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{logging, stopping};

/// How long saving everything can take before Windows thinks something's wrong, which
/// also applies while the host shuts down.
const TIME_TO_STOP: Duration = Duration::from_secs(60);

const FAILED: u32 = 1;

const NEEDS_ADMIN: &str = "reaching the Windows service manager, which needs an administrator";

/// The installers register the service, with Windows starting it as
/// `service run`.
#[derive(Debug, PartialEq, Subcommand)]
pub enum ServiceCommand {
    /// What Windows starts, which can't be run by hand
    Run,
}

pub struct Service {
    pub name: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    /// What its log files are called.
    pub log_name: &'static str,
}

struct Starting {
    service: &'static Service,
    config: PathBuf,
    work: Box<dyn FnOnce(PathBuf) -> Result<()> + Send>,
}

// Windows calls `service_main` with nothing of ours, so these are how it gets at them.
static STARTING: Mutex<Option<Starting>> = Mutex::new(None);
static STATUS: Mutex<Option<ServiceStatusHandle>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Hands over to Windows until the service has stopped.
pub fn run(
    service: &'static Service,
    config: &Path,
    work: impl FnOnce(PathBuf) -> Result<()> + Send + 'static,
) -> Result<()> {
    *STARTING.lock().unwrap() = Some(Starting {
        service,
        config: std::path::absolute(config).context("finding the config file")?,
        work: Box::new(work),
    });
    service_dispatcher::start(service.name, ffi_service_main)
        .context("connecting to Windows as a service, which only Windows can start")
}

fn service_main(_arguments: Vec<OsString>) {
    let starting = STARTING.lock().unwrap().take();
    if let Some(starting) = starting {
        // With no terminal and the log maybe not open, there's nowhere left to say why.
        let _ = run_reporting_to_windows(starting);
    }
}

fn run_reporting_to_windows(starting: Starting) -> Result<()> {
    let status = service_control_handler::register(starting.service.name, on_control)?;
    *STATUS.lock().unwrap() = Some(status);

    // Running from the start, because migrations can outlast the 30 seconds Windows
    // allows for starting up.
    status.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        0,
        Duration::ZERO,
    ))?;

    let code = match catch_unwind(AssertUnwindSafe(|| prepare_and_work(starting))) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            tracing::error!(error = format!("{error:#}"), "stopped by an error");
            FAILED
        }
        // The panic hook has already logged it.
        Err(_) => FAILED,
    };

    status.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        code,
        Duration::ZERO,
    ))?;
    Ok(())
}

/// Relative paths in the config mean the config's folder, not the system folder a
/// service starts in.
fn prepare_and_work(starting: Starting) -> Result<()> {
    let folder = starting
        .config
        .parent()
        .ok_or_else(|| anyhow!("the config file has no folder"))?;
    std::env::set_current_dir(folder).with_context(|| format!("moving to {}", folder.display()))?;
    logging::to_files(&folder.join("logs"), starting.service.log_name)?;
    (starting.work)(starting.config)
}

fn on_control(control: ServiceControl) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop | ServiceControl::Preshutdown => {
            if let Some(status) = *STATUS.lock().unwrap() {
                let _ = status.set_service_status(service_status(
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    0,
                    TIME_TO_STOP,
                ));
            }
            stopping::request();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

fn service_status(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    code: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted,
        exit_code: match code {
            0 => ServiceExitCode::Win32(0),
            code => ServiceExitCode::ServiceSpecific(code),
        },
        // Only a pending state counts these, and stopping has just the one step.
        checkpoint: u32::from(current_state == ServiceState::StopPending),
        wait_hint,
        process_id: None,
    }
}

/// Restarts the service so it reads a changed config, if it's installed and
/// running. A stopped service reads the config when it next starts.
pub fn restart_if_running(service: &Service) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context(NEEDS_ADMIN)?;
    let installed = match manager.open_service(
        OsStr::new(service.name),
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START,
    ) {
        Ok(installed) => installed,
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("finding the {} service", service.name));
        }
    };
    if installed.query_status()?.current_state != ServiceState::Running {
        return Ok(());
    }

    installed.stop()?;
    anyhow::ensure!(
        stopped_in_time(&installed)?,
        "{} didn't stop to restart, so it still has the old config",
        service.name
    );
    installed
        .start::<&OsStr>(&[])
        .with_context(|| format!("starting {} again", service.name))?;
    println!("Restarted {}.", service.name);
    Ok(())
}

const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

fn stopped_in_time(installed: &windows_service::service::Service) -> Result<bool> {
    let deadline = Instant::now() + TIME_TO_STOP;
    while installed.query_status()?.current_state != ServiceState::Stopped {
        if Instant::now() > deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(250));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pending_stop_counts_as_making_progress() {
        let status =
            |state| service_status(state, ServiceControlAccept::empty(), 0, Duration::ZERO);

        assert_eq!(status(ServiceState::StopPending).checkpoint, 1);
        assert_eq!(status(ServiceState::Running).checkpoint, 0);
    }

    #[test]
    fn a_failure_is_reported_as_ours() {
        let failed = service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            FAILED,
            Duration::ZERO,
        );

        assert_eq!(failed.exit_code, ServiceExitCode::ServiceSpecific(FAILED));
    }
}
