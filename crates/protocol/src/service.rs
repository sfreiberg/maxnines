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
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{logging, stopping};

/// How long saving everything can take before Windows thinks something's wrong, which
/// also applies while the machine shuts down.
const TIME_TO_STOP: Duration = Duration::from_secs(60);

/// Long enough that a config mistake doesn't fill the log, and a server that's starting
/// late doesn't use up the attempts.
const RESTART_AFTER: Duration = Duration::from_secs(30);

const FAILED: u32 = 1;

const NEEDS_ADMIN: &str = "reaching the Windows service manager, which needs an administrator";

#[derive(Debug, PartialEq, Subcommand)]
pub enum ServiceCommand {
    /// Install the Windows service, which starts with the machine
    Install,
    /// Stop and remove the Windows service, leaving the config and data in place
    Uninstall,
    /// What Windows starts, which can't be run by hand
    #[command(hide = true)]
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

/// Registers this program to start with the machine, restarting if it fails.
pub fn install(service: &Service, config: &Path) -> Result<()> {
    let config = std::path::absolute(config).context("finding the config file")?;
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .context(NEEDS_ADMIN)?;
    let installed = manager
        .create_service(
            &ServiceInfo {
                name: service.name.into(),
                display_name: service.display_name.into(),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: std::env::current_exe().context("finding this program")?,
                launch_arguments: launch_arguments(&config),
                dependencies: vec![],
                account_name: None,
                account_password: None,
            },
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .with_context(|| format!("creating the {} service", service.name))?;

    installed.set_description(service.description)?;
    installed.set_preshutdown_timeout(TIME_TO_STOP)?;
    installed.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: RESTART_AFTER,
        }]),
    })?;
    // Otherwise only a crash counts as failing, and not stopping with an error.
    installed.set_failure_actions_on_non_crash_failures(true)?;

    println!("Installed {}. Start it with:", service.name);
    println!("  Start-Service {}", service.name);
    Ok(())
}

fn launch_arguments(config: &Path) -> Vec<OsString> {
    vec![
        "--config".into(),
        config.into(),
        "service".into(),
        "run".into(),
    ]
}

/// Windows only removes a service once it's stopped, so this stops it first.
pub fn uninstall(service: &Service) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context(NEEDS_ADMIN)?;
    let installed = manager
        .open_service(
            OsStr::new(service.name),
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("finding the {} service", service.name))?;

    if installed.query_status()?.current_state == ServiceState::Running {
        installed.stop()?;
    }
    let deadline = Instant::now() + TIME_TO_STOP;
    while installed.query_status()?.current_state != ServiceState::Stopped {
        if Instant::now() > deadline {
            println!("{} is taking a while to stop.", service.name);
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }

    installed.delete()?;
    println!("Removed {}.", service.name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_starts_it_with_the_config_it_was_installed_with() {
        let arguments = launch_arguments(Path::new(r"C:\Program Data\agent.hcl"));

        assert_eq!(
            arguments,
            ["--config", r"C:\Program Data\agent.hcl", "service", "run"]
        );
    }

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
